# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import hashlib
import attr

from cryptodatahub.tls.algorithm import TlsECPointFormat, TlsSignatureAndHashAlgorithm

from cryptoparser.tls.extension import TlsExtensionType, TlsNamedCurve
from cryptoparser.tls.subprotocol import TlsCipherSuite
from cryptoparser.tls.version import TlsProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerBase
from cryptolyzer.common.result import AnalyzerResultBase

from cryptolyzer.fingerprint.tag import parse_ja3_tag, parse_ja4_raw_tag


@attr.s
class JA3ClientTag():
    tag = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def get_supported_schemes(cls):
        return {
            'ja3'
        }

    @classmethod
    def get_scheme(cls):
        return 'ja3'

    @classmethod
    def from_scheme(cls, scheme, address, l4_socket_params):  # pylint: disable=unused-argument
        return JA3ClientTag(address)


@attr.s
class JA4ClientTag():
    tag = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def get_supported_schemes(cls):
        return {
            'ja4'
        }

    @classmethod
    def get_scheme(cls):
        return 'ja4'

    @classmethod
    def from_scheme(cls, scheme, address, l4_socket_params):  # pylint: disable=unused-argument
        return JA4ClientTag(address)


@attr.s
class AnalyzerResultDecode(AnalyzerResultBase):
    target: str = attr.ib(validator=attr.validators.instance_of(str))
    tls_protocol_version = attr.ib(
        validator=attr.validators.instance_of(TlsProtocolVersion),
    )
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
    target_hash = attr.ib(init=False)

    def __attrs_post_init__(self):
        tag_hash = hashlib.md5()
        tag_hash.update(self.target.encode('ascii'))
        self.target_hash = tag_hash.hexdigest()


@attr.s
class AnalyzerResultDecodeJA4(AnalyzerResultBase):
    target: str = attr.ib(validator=attr.validators.instance_of(str))
    tls_protocol_version = attr.ib(
        validator=attr.validators.instance_of(TlsProtocolVersion),
    )
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


class AnalyzerDecode(AnalyzerBase):
    @classmethod
    def get_name(cls):
        return 'decode'

    @classmethod
    def get_help(cls):
        return 'Decode fingerprint(s)'

    @classmethod
    def get_clients(cls):
        return [JA3ClientTag, JA4ClientTag]

    @classmethod
    def get_default_scheme(cls):
        return 'ja3'

    def analyze(self, analyzable):
        super().analyze(analyzable)

        if isinstance(analyzable, JA4ClientTag):
            return AnalyzerResultDecodeJA4(analyzable.tag, *parse_ja4_raw_tag(analyzable.tag))

        return AnalyzerResultDecode(analyzable.tag, *parse_ja3_tag(analyzable.tag))
