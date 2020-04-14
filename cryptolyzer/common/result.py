# -*- coding: utf-8 -*-

import six
import attr

from cryptoparser.common.base import Serializable


@attr.s
class AnalyzerTarget(Serializable):
    scheme = attr.ib(validator=attr.validators.instance_of(six.string_types))
    address = attr.ib(validator=attr.validators.instance_of(six.string_types))
    ip = attr.ib(validator=attr.validators.instance_of(six.string_types))
    port = attr.ib(validator=attr.validators.instance_of(int))


@attr.s
class AnalyzerTargetTls(AnalyzerTarget):
    proto_version = attr.ib(default=None)

    @staticmethod
    def from_l7_client(l7_client, proto_version=None):
        return AnalyzerTargetTls(l7_client.get_scheme(), l7_client.address, l7_client.ip, l7_client.port, proto_version)


@attr.s
class AnalyzerResultBase(Serializable):
    target = attr.ib()


@attr.s
class AnalyzerResultTls(AnalyzerResultBase):
    pass
