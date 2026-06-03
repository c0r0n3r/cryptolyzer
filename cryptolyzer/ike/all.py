# SPDX-License-Identifier: MPL-2.0

import typing

import attr

from cryptolyzer.common.analyzer import AnalyzerIKEBase
from cryptolyzer.common.result import AnalyzerResultIKE, AnalyzerTargetIke
from cryptolyzer.ike.ciphers import (
    AnalyzerCiphers,
    AnalyzerResultIkev1Ciphers,
    AnalyzerResultIkev2Ciphers,
)
from cryptolyzer.ike.extensions import (
    AnalyzerExtensions,
    AnalyzerResultIkev1Extensions,
    AnalyzerResultIkev2Extensions,
)
from cryptolyzer.ike.versions import AnalyzerVersions, AnalyzerResultVersions


@attr.s
class AnalyzerResultAll(AnalyzerResultIKE):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to all analyzers.

    :param versions: supported protocol versions (IKEv1/IKEv2).
    :param ciphers: the supported transforms.
    :param extensions: detected IKE extensions advertised during SA setup.
    """

    versions: typing.Optional[AnalyzerResultVersions] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultVersions)),
        metadata={'human_readable_name': 'Supported Protocol Versions'}
    )
    ciphers: typing.Optional[typing.Union[AnalyzerResultIkev1Ciphers, AnalyzerResultIkev2Ciphers]] = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of((AnalyzerResultIkev1Ciphers, AnalyzerResultIkev2Ciphers))
        ),
        metadata={'human_readable_name': 'Supported Cipher Suites'}
    )
    extensions: typing.Optional[typing.Union[AnalyzerResultIkev1Extensions, AnalyzerResultIkev2Extensions]] = attr.ib(
        validator=attr.validators.optional(
            attr.validators.instance_of((AnalyzerResultIkev1Extensions, AnalyzerResultIkev2Extensions))
        ),
        metadata={'human_readable_name': 'Extensions'}
    )


class AnalyzerAll(AnalyzerIKEBase):
    @classmethod
    def get_name(cls):
        return 'all'

    @classmethod
    def get_help(cls):
        return 'Check all supported features of the server(s)'

    @classmethod
    def get_clients(cls):
        """Get list of client classes.

        :return: List of client classes
        :rtype: list
        """
        return []

    def analyze(self, analyzable, protocol_version):
        """
        :type analyzable: AnalyzerTargetIKE
        :type protocol_version: IkeVersion
        :rtype: AnalyzerResultAll
        """
        super().analyze(analyzable, protocol_version)
        versions = None
        ciphers = None
        extensions = None

        try:
            versions = AnalyzerVersions().analyze(analyzable, protocol_version)
        except Exception:  # pylint: disable=broad-except
            pass

        try:
            ciphers = AnalyzerCiphers().analyze(analyzable, protocol_version)
        except Exception:  # pylint: disable=broad-except
            pass

        try:
            extensions = AnalyzerExtensions().analyze(analyzable, protocol_version)
        except Exception:  # pylint: disable=broad-except
            pass

        return AnalyzerResultAll(
            target=AnalyzerTargetIke.from_l7_client(analyzable),
            versions=versions,
            ciphers=ciphers,
            extensions=extensions,
        )
