# -*- coding: utf-8 -*-

import typing

import attr

from cryptodatahub.common.parameter import DHParamWellKnownParams
from cryptodatahub.ike.algorithm import (
    Ikev1DiffieHellmanGroup,
    Ikev2DiffieHellmanGroup,
)

from cryptoparser.ike.version import IsakmpVersion

from cryptolyzer.ike.dh import AnalyzerDHBase
from cryptolyzer.common.result import AnalyzerResultIKE


@attr.s
class AnalyzerResultDHParams(AnalyzerResultIKE):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to the negotiable transforms.

    :param transforms: the supported transforms.
    :param transform_preference: whether server has transform preference.
    """

    groups: typing.List[typing.Union[Ikev1DiffieHellmanGroup, Ikev2DiffieHellmanGroup]] = attr.ib(
        validator=attr.validators.deep_iterable(
            attr.validators.instance_of((Ikev1DiffieHellmanGroup, Ikev2DiffieHellmanGroup))
        )
    )
    key_reused: typing.Optional[bool] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )


class AnalyzerDHParams(AnalyzerDHBase):
    @classmethod
    def get_name(cls):
        return 'dhparams'

    @classmethod
    def get_help(cls):
        return 'Check which Diffie-Hellman groups supported by the server(s)'

    @classmethod
    def _get_dh_groups(cls, dh_group_type):
        return list(filter(
            lambda dh_group: isinstance(dh_group.value.key_parameter.value, DHParamWellKnownParams),
            dh_group_type
        ))

    @classmethod
    def _get_dh_group_name(cls):
        return 'Diffie-Hellman group'

    def analyze(self, analyzable, protocol_version: IsakmpVersion):
        """
        :type analyzable: AnalyzerTargetIKE
        :type protocol_version: IsakmpVersion
        """

        dh_groups, key_reused = self._analyze(analyzable, protocol_version)

        return AnalyzerResultDHParams(
            target=analyzable,
            groups=dh_groups,
            key_reused=key_reused,
        )
