#!/usr/bin/env python
# -*- coding: utf-8 -*-

import attr
import six


from cryptodatahub.common.algorithm import KeyExchange
from cryptodatahub.common.key import PublicKeySize

from cryptodatahub.ssh.algorithm import SshKexAlgorithm

from cryptoparser.common.base import Serializable

from cryptoparser.ssh.subprotocol import (
    SshDHGroupExchangeGroup,
    SshDHGroupExchangeReply,
    SshMessageCode,
)
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.dhparam import get_dh_public_key_from_bytes
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultSsh, AnalyzerTargetSsh
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.ssh.client import L7ServerSshGexParams, SshKeyExchangeInitAnyAlgorithm
from cryptolyzer.ssh.ciphers import AnalyzerCiphers


@attr.s
class AnalyzerResultGroupExchange(object):
    """
    :class: Analyzer result relates to DH group exchange

    :param gex_algorithms: List of the negotiable group exchange algorithms.
    :param key_sizes: List of the negotiable key size during the group exchange.
    :param bounds_tolerated: Whether server tolerate the range of the supported key sizes by the client.
    """

    gex_algorithms = attr.ib(
        attr.validators.deep_iterable(attr.validators.instance_of(SshKexAlgorithm)),
        metadata={'human_readable_name': 'Group Exchange Algorithms'}
    )
    key_sizes = attr.ib(attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(PublicKeySize))
    )
    bounds_tolerated = attr.ib(attr.validators.instance_of(bool))


@attr.s
class AnalyzerResultKeyExchange(Serializable):
    """
    :class: Analyzer result relates to DH key exchange

    :param kex_algorithms: List of the negotiable key exchange algorithms.
    """

    kex_algorithms = attr.ib(attr.validators.deep_iterable(attr.validators.instance_of(SshKexAlgorithm)))

    def _as_markdown(self, level):
        return self._markdown_result([
            '{} ({})'.format(kex_algorithm.value.code, kex_algorithm.value.key_size)
            for kex_algorithm in self.kex_algorithms
        ], level)


@attr.s
class AnalyzerResultDHParams(AnalyzerResultSsh):
    """
    :class: Analyzer result relates to Diffie-Hellman (DH) key exchange

    :param key_exchange: Key exchange related analyzer result, when supported.
    :param group_exchange: Group exchange related analyzer result, when supported.
    """

    key_exchange = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultKeyExchange))
    )
    group_exchange = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(AnalyzerResultGroupExchange))
    )


class AnalyzerDHParams(AnalyzerSshBase):
    @classmethod
    def get_name(cls):
        return 'dhparams'

    @classmethod
    def get_help(cls):
        return 'Check DH parameters offered by the server(s)'

    @classmethod
    def _get_negotiable_key_sizes(cls, analyzable, gex_algorithms):
        gex_min_size = 1
        gex_max_size = 8192
        gex_tolerates_bounds = True
        gex_key_sizes = set()
        while True:
            try:
                key_exchange_init_message = SshKeyExchangeInitAnyAlgorithm(kex_algorithms=[gex_algorithms[0], ])
                server_messages = analyzable.do_handshake(
                    key_exchange_init_message=key_exchange_init_message,
                    gex_params=L7ServerSshGexParams(
                        gex_min=gex_min_size, gex_max=gex_max_size, gex_number=gex_min_size
                    ),
                    last_message_type=SshMessageCode.DH_GEX_REPLY,
                )
            except NetworkError as e:
                if e.error == NetworkErrorType.NO_RESPONSE:
                    break

                raise  # pragma: no cover

            dh_group_exchange_group = server_messages[SshDHGroupExchangeGroup]
            dh_group_exchange_reply = server_messages[SshDHGroupExchangeReply]

            dh_public_key = get_dh_public_key_from_bytes(
                dh_group_exchange_group.p, dh_group_exchange_group.g, dh_group_exchange_reply.ephemeral_public_key
            )
            if gex_min_size > gex_max_size:
                break

            if dh_public_key.key_size in gex_key_sizes:
                if gex_min_size > dh_public_key.key_size:
                    gex_tolerates_bounds = False

                gex_min_size = ((gex_min_size // 1024) + 1) * 1024
            else:
                gex_min_size = dh_public_key.key_size + 1

            if dh_public_key.key_size not in gex_key_sizes:
                gex_key_sizes.add(dh_public_key.key_size)
                LogSingleton().log(level=60, msg=six.u(
                    'Server offers custom DH public parameter with size %d-bit (%s)') % (
                        dh_public_key.key_size, SshProtocolVersion(SshVersion.SSH2),
                    )
                )

        return AnalyzerResultGroupExchange(
            gex_algorithms,
            [PublicKeySize(KeyExchange.DHE, gex_key_size) for gex_key_size in sorted(gex_key_sizes)],
            gex_tolerates_bounds
        )

    def analyze(self, analyzable):
        LogSingleton().disabled = True
        analyzer_result = AnalyzerCiphers().analyze(analyzable)
        LogSingleton().disabled = False

        gex_algorithms = []
        kex_algorithms = []

        algorithms = filter(
            lambda kex_algorithm: (
                isinstance(kex_algorithm, SshKexAlgorithm) and
                kex_algorithm.value.kex == KeyExchange.DHE
                ),
            analyzer_result.kex_algorithms
        )

        for kex_algorithm in algorithms:
            if kex_algorithm.value.key_size is None:
                gex_algorithms.append(kex_algorithm)
            else:
                kex_algorithms.append(kex_algorithm)

        for algorithm in kex_algorithms:
            LogSingleton().log(level=60, msg=six.u(
                'Server offers well-known DH public parameter with size %s-bit (%s)') % (
                    'unknown' if isinstance(algorithm, six.string_types) else str(algorithm.value.key_size),
                    algorithm if isinstance(algorithm, six.string_types) else algorithm.value.code,
                )
            )

        return AnalyzerResultDHParams(
            AnalyzerTargetSsh.from_l7_client(analyzable),
            AnalyzerResultKeyExchange(kex_algorithms) if kex_algorithms else None,
            self._get_negotiable_key_sizes(analyzable, gex_algorithms) if gex_algorithms else None
        )
