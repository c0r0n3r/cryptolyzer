#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import OrderedDict

from cryptoparser.common.base import JSONSerializable


class AnalyzerTarget(JSONSerializable):
    def __init__(self, scheme, address, ip, port):
        self.scheme = scheme
        self.address = address
        self.ip = ip
        self.port = port

    def as_json(self):
        return OrderedDict([
            ('scheme', self.scheme),
            ('address', self.address),
            ('ip', self.ip),
            ('port', self.port),
        ])


class AnalyzerTargetTls(AnalyzerTarget):
    def __init__(self, scheme, address, ip, port, proto_version=None):  # pylint: disable=too-many-arguments
        super(AnalyzerTargetTls, self).__init__(scheme, address, ip, port)

        self.proto_version = proto_version

    def as_json(self):
        target_as_json = super(AnalyzerTargetTls, self).as_json()
        target_as_json['proto_version'] = self.proto_version

        return target_as_json

    @staticmethod
    def from_l7_client(l7_client, proto_version=None):
        return AnalyzerTargetTls(l7_client.get_scheme(), l7_client.address, l7_client.ip, l7_client.port, proto_version)


class AnalyzerResultBase(JSONSerializable):
    def __init__(self, target):
        self.target = target


class AnalyzerResultTls(AnalyzerResultBase):
    pass
