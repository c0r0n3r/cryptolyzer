# SPDX-License-Identifier: MPL-2.0

import hashlib
import attr

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.tls.algorithm import TlsECPointFormat, TlsSignatureAndHashAlgorithm

from cryptoparser.common.parse import ComposerBinary

from cryptoparser.tls.algorithm import TlsSignatureAndHashAlgorithmFactory
from cryptoparser.tls.ciphersuite import TlsCipherSuiteFactory
from cryptoparser.tls.extension import (
    TlsECPointFormatFactory,
    TlsExtensionType,
    TlsExtensionTypeFactory,
    TlsNamedCurve,
    TlsNamedCurveFactory,
)
from cryptoparser.tls.subprotocol import TlsCipherSuite, TlsCipherSuiteVector
from cryptoparser.tls.version import TlsProtocolVersion

from cryptolyzer.common.result import FingerprintBase


_JA4_VERSION_CODES = {
    '13': 0x0304, '12': 0x0303, '11': 0x0302, '10': 0x0301,
    's3': 0x0300, 's2': 0x0002,
    'd1': 0xfeff, 'd2': 0xfefd, 'd3': 0xfefc,
}


def _numeric_string_to_bytes(numeric, size):
    composer = ComposerBinary()
    composer.compose_numeric(int(numeric), size)
    return composer.composed_bytes


def _hex_list_to_items(hex_list, factory):
    return [
        factory.parse_exact_size(bytes.fromhex(item))
        for item in hex_list.split(',')
    ] if hex_list else []


def parse_ja3_tag(tag):
    tls_protocol_version, cipher_suites, extension_types, named_curves, ec_point_formats = tag.split(',')

    tls_protocol_version = TlsProtocolVersion.parse_exact_size(_numeric_string_to_bytes(tls_protocol_version, 2))

    if cipher_suites:
        cipher_suites = cipher_suites.split('-')
        cipher_suites_header = _numeric_string_to_bytes(len(cipher_suites) * 2, 2)
        cipher_suites = b''.join([
            bytes(_numeric_string_to_bytes(cipher_suite, 2))
            for cipher_suite in cipher_suites
        ])
        cipher_suites = list(TlsCipherSuiteVector.parse_exact_size(cipher_suites_header + cipher_suites))
    else:
        cipher_suites = []

    extension_types = [
        TlsExtensionTypeFactory.parse_exact_size(_numeric_string_to_bytes(extension, 2))
        for extension in extension_types.split('-')
    ] if extension_types else []

    named_curves = [
        TlsNamedCurveFactory.parse_exact_size(_numeric_string_to_bytes(named_curve, 2))
        for named_curve in named_curves.split('-')
    ] if named_curves else []

    ec_point_formats = [
        TlsECPointFormatFactory.parse_exact_size(_numeric_string_to_bytes(ec_point_format, 1))
        for ec_point_format in ec_point_formats.split('-')
    ] if ec_point_formats else []

    return tls_protocol_version, cipher_suites, extension_types, named_curves, ec_point_formats


def parse_ja4_raw_tag(tag):
    parts = tag.split('_')
    # only the raw (ja4_r) form is reversible; the hashed form has two hash fields instead of three lists
    if len(parts) != 4:
        raise InvalidValue(tag, JA4Fingerprint)

    header, cipher_hexes, extension_hexes, signature_algorithm_hexes = parts

    tls_protocol_version = TlsProtocolVersion.parse_exact_size(
        _JA4_VERSION_CODES[header[1:3]].to_bytes(2, 'big')
    )

    return (
        tls_protocol_version,
        header[3] == 'd',
        header[8:10],
        _hex_list_to_items(cipher_hexes, TlsCipherSuiteFactory),
        _hex_list_to_items(extension_hexes, TlsExtensionTypeFactory),
        _hex_list_to_items(signature_algorithm_hexes, TlsSignatureAndHashAlgorithmFactory),
    )


@attr.s
class JA3Fingerprint(FingerprintBase):
    tag = attr.ib(validator=attr.validators.instance_of(str))
    tls_protocol_version = attr.ib(validator=attr.validators.instance_of(TlsProtocolVersion))
    cipher_suites = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(TlsCipherSuite))
    )
    extension_types = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(TlsExtensionType))
    )
    named_curves = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(TlsNamedCurve))
    )
    ec_point_formats = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(TlsECPointFormat))
    )
    tag_hash = attr.ib(init=False, metadata={'human_readable_name': 'Hash'})

    def __attrs_post_init__(self):
        tag_hash = hashlib.md5()
        tag_hash.update(self.tag.encode('ascii'))
        self.tag_hash = tag_hash.hexdigest()

    @classmethod
    def from_tag(cls, tag):
        return cls(tag, *parse_ja3_tag(tag))


@attr.s
class JA4Fingerprint(FingerprintBase):  # pylint: disable=too-many-instance-attributes
    tag = attr.ib(validator=attr.validators.instance_of(str))
    tag_original = attr.ib(validator=attr.validators.instance_of(str))
    raw = attr.ib(validator=attr.validators.instance_of(str))
    raw_original = attr.ib(validator=attr.validators.instance_of(str))
    tls_protocol_version = attr.ib(validator=attr.validators.instance_of(TlsProtocolVersion))
    server_name = attr.ib(validator=attr.validators.instance_of(bool))
    application_layer_protocol = attr.ib(validator=attr.validators.instance_of(str))
    cipher_suites = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(TlsCipherSuite))
    )
    extension_types = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(TlsExtensionType))
    )
    signature_algorithms = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(TlsSignatureAndHashAlgorithm))
    )

    @classmethod
    def from_tags(cls, tag, tag_original, raw, raw_original):
        return cls(tag, tag_original, raw, raw_original, *parse_ja4_raw_tag(raw_original))


@attr.s
class TlsFingerprint(FingerprintBase):
    ja3 = attr.ib(
        validator=attr.validators.instance_of(JA3Fingerprint),
        metadata={'human_readable_name': 'JA3'},
    )
    ja4 = attr.ib(
        validator=attr.validators.instance_of(JA4Fingerprint),
        metadata={'human_readable_name': 'JA4'},
    )


@attr.s
class SshFingerprint(FingerprintBase):
    hassh = attr.ib(
        validator=attr.validators.instance_of(str),
        metadata={'human_readable_name': 'HASSH'},
    )
