# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import collections
import enum

import attr
import urllib3

from cryptodatahub.common.algorithm import Authentication
from cryptodatahub.common.grade import Grade, GradeableSimple
from cryptodatahub.common.types import CryptoDataParamsNamed
from cryptodatahub.common.utils import hash_bytes

from cryptodatahub.ssh.algorithm import SshHostKeyType
from cryptoparser.ssh.key import SshPublicKeyBase
from cryptoparser.ssh.subprotocol import (
    SshDHKeyExchangeReplyBase,
    SshMessageCode,
)

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultSsh, AnalyzerTargetSsh
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.dnsrec.client import L7ClientDns

from cryptolyzer.ssh.ciphers import AnalyzerCiphers
from cryptolyzer.ssh.client import (
    SshDisconnect,
    SshKeyExchangeInitHostKeyDSS,
    SshKeyExchangeInitHostKeyECDSA,
    SshKeyExchangeInitHostKeyED25519,
    SshKeyExchangeInitHostKeyRSA,
    SshKeyExchangeInitHostCertificateV00DSS,
    SshKeyExchangeInitHostCertificateV00RSA,
    SshKeyExchangeInitHostCertificateV01DSS,
    SshKeyExchangeInitHostCertificateV01RSA,
    SshKeyExchangeInitHostCertificateV01ECDSA,
    SshKeyExchangeInitHostCertificateV01ED25519,
    SshKeyExchangeInitX509CertificateDSS,
    SshKeyExchangeInitX509CertificateRSA,
    SshKeyExchangeInitX509CertificateChainDSA,
    SshKeyExchangeInitX509CertificateChainRSA,
    SshKeyExchangeInitX509CertificateChainECDSA,
)


@attr.s(frozen=True)
class SshFpVerificationStatusParams(CryptoDataParamsNamed, GradeableSimple):
    _grade = attr.ib(validator=attr.validators.instance_of(Grade))

    @property
    def grade(self):
        return self._grade


class SshFpVerificationStatus(enum.Enum):
    MISSING = SshFpVerificationStatusParams(name='missing', long_name=None, grade=Grade.DEPRECATED)
    MATCH = SshFpVerificationStatusParams(name='match', long_name=None, grade=Grade.SECURE)
    MISMATCH = SshFpVerificationStatusParams(name='mismatch', long_name=None, grade=Grade.INSECURE)


@attr.s
class SshPublicKeyWithSshfpState:
    public_key = attr.ib(validator=attr.validators.instance_of(SshPublicKeyBase))
    sshfp_status = attr.ib(
        validator=attr.validators.instance_of(SshFpVerificationStatus),
        metadata={'human_readable_name': 'DNS Fingerprint Status'},
    )


@attr.s
class AnalyzerResultPublicKeys(AnalyzerResultSsh):
    """
    :class: Analyzer result relates to a host keys/certificates.

    :param public_keys: List of host keys/certificates, each paired with its SSHFP DNS verification status.
    """

    public_keys = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(SshPublicKeyWithSshfpState))
    )


class AnalyzerPublicKeys(AnalyzerSshBase):
    _KEY_EXCHANGE_INIT_MESSAGES_BY_TYPE = collections.OrderedDict([
        ((SshHostKeyType.HOST_KEY, Authentication.DSS), SshKeyExchangeInitHostKeyDSS()),
        ((SshHostKeyType.HOST_KEY, Authentication.ECDSA), SshKeyExchangeInitHostKeyECDSA()),
        ((SshHostKeyType.HOST_KEY, Authentication.EDDSA), SshKeyExchangeInitHostKeyED25519()),
        ((SshHostKeyType.HOST_KEY, Authentication.RSA), SshKeyExchangeInitHostKeyRSA()),
        ((SshHostKeyType.HOST_CERTIFICATE, Authentication.DSS), SshKeyExchangeInitHostCertificateV00DSS()),
        ((SshHostKeyType.HOST_CERTIFICATE, Authentication.RSA), SshKeyExchangeInitHostCertificateV00RSA()),
        ((SshHostKeyType.HOST_CERTIFICATE, Authentication.DSS), SshKeyExchangeInitHostCertificateV01DSS()),
        ((SshHostKeyType.HOST_CERTIFICATE, Authentication.RSA), SshKeyExchangeInitHostCertificateV01RSA()),
        ((SshHostKeyType.HOST_CERTIFICATE, Authentication.ECDSA), SshKeyExchangeInitHostCertificateV01ECDSA()),
        ((SshHostKeyType.HOST_CERTIFICATE, Authentication.EDDSA), SshKeyExchangeInitHostCertificateV01ED25519()),
        ((SshHostKeyType.X509_CERTIFICATE, Authentication.DSS), SshKeyExchangeInitX509CertificateDSS()),
        ((SshHostKeyType.X509_CERTIFICATE, Authentication.RSA), SshKeyExchangeInitX509CertificateRSA()),
        ((SshHostKeyType.X509_CERTIFICATE_CHAIN, Authentication.DSS), SshKeyExchangeInitX509CertificateChainDSA()),
        ((SshHostKeyType.X509_CERTIFICATE_CHAIN, Authentication.ECDSA), SshKeyExchangeInitX509CertificateChainECDSA()),
        ((SshHostKeyType.X509_CERTIFICATE_CHAIN, Authentication.RSA), SshKeyExchangeInitX509CertificateChainRSA()),
    ])

    @classmethod
    def get_name(cls):
        return 'pubkeys'

    @classmethod
    def get_help(cls):
        return 'Check which public keys or certificates used by the server(s)'

    @classmethod
    def _get_dh_key_exchange_reply_message_class(cls, server_messages):
        return next(iter(filter(
            lambda server_message: issubclass(server_message, SshDHKeyExchangeReplyBase),
            server_messages
        )))

    @classmethod
    def _compute_sshfp_status(cls, sshfp_records, public_key):
        key_auth = public_key.host_key_algorithm.value.signature.value.key_type
        matching_records = [
            r for r in sshfp_records
            if r.algorithm.value.algorithm == key_auth
        ]
        if not matching_records:
            return SshFpVerificationStatus.MISSING

        for record in matching_records:
            expected = hash_bytes(record.fingerprint_type.value.hash, public_key.key_bytes)
            if record.fingerprint == expected:
                return SshFpVerificationStatus.MATCH

        return SshFpVerificationStatus.MISMATCH

    @classmethod
    def _get_sshfp_states(cls, address, host_public_keys):
        try:
            dns_client = L7ClientDns.from_uri(urllib3.util.parse_url(f'dns://{address}'))
            sshfp_records = dns_client.get_sshfp_records()
        except NetworkError:
            sshfp_records = []

        return [
            SshPublicKeyWithSshfpState(host_public_key, cls._compute_sshfp_status(sshfp_records, host_public_key))
            for host_public_key in host_public_keys
        ]

    def analyze(self, analyzable):
        super().analyze(analyzable)
        LogSingleton().disabled = True
        analyzer_result = AnalyzerCiphers().analyze(analyzable)
        LogSingleton().disabled = False
        host_key_types = set(map(
            lambda host_key_algorithm: (
                host_key_algorithm.value.key_type,
                host_key_algorithm.value.signature.value.key_type
            ),
            filter(
                lambda host_key_algorithm: (
                    not isinstance(host_key_algorithm, str) and
                    (
                        host_key_algorithm.value.key_type,
                        host_key_algorithm.value.signature.value.key_type,
                    ) in self._KEY_EXCHANGE_INIT_MESSAGES_BY_TYPE
                ),
                analyzer_result.host_key_algorithms,
            ),
        ))

        server_dhe_ecdhe_kex = list(filter(
            lambda kex: not isinstance(kex, str),
            analyzer_result.kex_algorithms
        ))

        host_public_keys = []
        for host_key_type, key_exchange_init_message in self._KEY_EXCHANGE_INIT_MESSAGES_BY_TYPE.items():
            if host_key_type not in host_key_types:
                continue

            kex_algorithms = [
                kex_algorithm
                for kex_algorithm in server_dhe_ecdhe_kex
                if kex_algorithm in key_exchange_init_message.kex_algorithms
            ]

            key_exchange_init_message = self._build_limited_key_exchange_init_message(
                key_exchange_init_message,
                analyzer_result,
                keep_from_template=('host_key_algorithms',),
                server_overrides={
                    'kex_algorithms': kex_algorithms,
                },
            )

            try:
                server_messages = analyzable.do_handshake(
                    key_exchange_init_message=key_exchange_init_message,
                    last_message_type=SshMessageCode.NEWKEYS
                )
                dh_key_exchange_reply_message = server_messages[
                    self._get_dh_key_exchange_reply_message_class(server_messages)
                ]
            except NetworkError as e:
                if e.error == NetworkErrorType.NO_RESPONSE:
                    pass
                else:
                    raise e
            except SshDisconnect:
                pass
            except StopIteration:
                pass
            else:
                host_public_key = dh_key_exchange_reply_message.host_public_key
                host_public_keys.append(host_public_key)
                LogSingleton().log(
                    level=60, msg=f'Server offers {host_public_key.host_key_algorithm.value.code} host key'
                )

        return AnalyzerResultPublicKeys(
            AnalyzerTargetSsh.from_l7_client(analyzable),
            self._get_sshfp_states(analyzable.address, host_public_keys),
        )
