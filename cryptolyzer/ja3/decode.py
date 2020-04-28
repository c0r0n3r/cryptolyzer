# -*- coding: utf-8 -*-

import hashlib
import six

from cryptoparser.common.parse import ComposerBinary

from cryptoparser.tls.extension import TlsExtensionTypeFactory, TlsNamedCurveFactory, TlsECPointFormatFactory
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector
from cryptoparser.tls.version import TlsProtocolVersionBase

from cryptolyzer.common.analyzer import AnalyzerBase
from cryptolyzer.common.result import AnalyzerResultBase


class JA3ClientTag(object):
    def __init__(self, tag):
        self.tag = tag

    @classmethod
    def get_supported_schemes(cls):
        return {
            'tag'
        }

    @classmethod
    def get_scheme(cls):
        return 'tag'

    @classmethod
    def from_scheme(cls, scheme, address):  # pylint: disable=unused-argument
        return JA3ClientTag(address)


class AnalyzerResultDecode(AnalyzerResultBase):
    def __init__(
            self,
            target,
            tls_protocol_version,
            cipher_suites,
            extension_types,
            named_curves,
            ec_point_formats
    ):  # pylint: disable=too-many-arguments
        super(AnalyzerResultDecode, self).__init__(six.text_type(target))

        self.tls_protocol_version = tls_protocol_version
        self.cipher_suites = cipher_suites
        self.extension_types = extension_types
        self.named_curves = named_curves
        self.ec_point_formats = ec_point_formats

        tag_hash = hashlib.md5()
        tag_hash.update(target.encode('ascii'))
        self.target_hash = tag_hash.hexdigest()


class AnalyzerDecode(AnalyzerBase):
    @classmethod
    def get_name(cls):
        return 'decode'

    @classmethod
    def get_help(cls):
        return 'Decode JA3 tag(s)'

    @classmethod
    def get_clients(cls):
        return [JA3ClientTag, ]

    @classmethod
    def get_default_scheme(cls):
        return 'tag'

    @staticmethod
    def _numeric_string_to_bytes(numeric, size):
        composer = ComposerBinary()
        composer.compose_numeric(int(numeric), size)
        return composer.composed_bytes

    def analyze(self, analyzable):
        tls_protocol_version, cipher_suites, extension_types, named_curves, ec_point_formats = analyzable.tag.split(',')

        tls_protocol_version = TlsProtocolVersionBase.parse_exact_size(
            self._numeric_string_to_bytes(tls_protocol_version, 2)
        )

        if cipher_suites:
            cipher_suites = cipher_suites.split('-')
            cipher_suites_header = self._numeric_string_to_bytes(len(cipher_suites) * 2, 2)
            cipher_suites = b''.join([
                bytes(self._numeric_string_to_bytes(cipher_suite, 2))
                for cipher_suite in cipher_suites
            ])
            cipher_suites = list(TlsCipherSuiteVector.parse_exact_size(cipher_suites_header + cipher_suites))
        else:
            cipher_suites = []

        extension_types = [
            TlsExtensionTypeFactory.parse_exact_size(self._numeric_string_to_bytes(extension, 2))
            for extension in extension_types.split('-')
        ] if extension_types else []

        named_curves = [
            TlsNamedCurveFactory.parse_exact_size(self._numeric_string_to_bytes(named_curve, 2))
            for named_curve in named_curves.split('-')
        ] if named_curves else []

        ec_point_formats = [
            TlsECPointFormatFactory.parse_exact_size(self._numeric_string_to_bytes(ec_point_format, 1))
            for ec_point_format in ec_point_formats.split('-')
        ] if ec_point_formats else []

        return AnalyzerResultDecode(
            analyzable.tag,
            tls_protocol_version,
            cipher_suites,
            extension_types,
            named_curves,
            ec_point_formats,
        )
