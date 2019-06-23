# -*- coding: utf-8 -*-

from collections import OrderedDict

import six
import attr

from cryptoparser.common.base import Serializable
from cryptoparser.tls.version import SslProtocolVersion, TlsProtocolVersionBase


@attr.s
class AnalyzerTarget(Serializable):
    scheme = attr.ib(validator=attr.validators.instance_of(six.string_types))
    address = attr.ib(validator=attr.validators.instance_of(six.string_types))
    ip = attr.ib(
        validator=attr.validators.instance_of(six.string_types),
        metadata={'human_readable_name': 'IP address'}
    )
    port = attr.ib(validator=attr.validators.instance_of(int))

    @staticmethod
    def from_l7_client(l7_client, proto_version=None):
        return AnalyzerTargetTls(l7_client.get_scheme(), l7_client.address, l7_client.ip, l7_client.port, proto_version)


@attr.s
class AnalyzerTargetTls(AnalyzerTarget):
    proto_version = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of((SslProtocolVersion, TlsProtocolVersionBase))),
        metadata={'human_readable_name': 'Protocol Version'}
    )

    @staticmethod
    def from_l7_client(l7_client, proto_version=None):
        return AnalyzerTargetTls(l7_client.get_scheme(), l7_client.address, l7_client.ip, l7_client.port, proto_version)


@attr.s
class AnalyzerTargetSsh(AnalyzerTarget):
    pass


@attr.s
class AnalyzerResultBase(Serializable):
    target = attr.ib()


@attr.s
class AnalyzerResultAllSupportedVersions(AnalyzerResultBase):
    results = attr.ib(validator=attr.validators.instance_of(OrderedDict))

    def _asdict(self):
        results = []
        for protocol_version, result in iter(self.results.items()):
            result_as_dict = result._asdict()

            results.append((protocol_version.identifier, result_as_dict))

        return OrderedDict([('target', self.target)] + results)


@attr.s
class AnalyzerResultTls(AnalyzerResultBase):
    pass


class AnalyzerResultSsh(AnalyzerResultBase):
    pass
