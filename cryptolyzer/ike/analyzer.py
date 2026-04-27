# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from cryptolyzer.common.analyzer import ProtocolHandlerIKEBase

from cryptolyzer.ike.versions import AnalyzerVersions


class ProtocolHandlerIKEVersionIndependent(ProtocolHandlerIKEBase):
    @classmethod
    def get_analyzers(cls):
        return (
            AnalyzerVersions,
        )

    @classmethod
    def get_protocol(cls):
        return 'ike'

    @classmethod
    def get_protocol_version(cls):
        return None
