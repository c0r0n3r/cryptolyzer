#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptography.hazmat.backends import default_backend as cryptography_default_backend
import cryptography.hazmat.primitives.asymmetric.dh as cryptography_dh

from cryptoparser.common.algorithm import KeyExchange
from cryptoparser.common.base import TwoByteEnumComposer, TwoByteEnumParsable
from cryptoparser.ssh.ciphersuite import SshKexAlgorithms
from cryptoparser.ssh.subprotocol import SshKexDHGexReply

from cryptolyzer.common.analyzer import AnalyzerSshBase
from cryptolyzer.common.dhparam import parse_dh_params
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultBase, DHParameter

from cryptolyzer.ssh.client import SshKeyExchangeInitAnyAlgorithm, SshDisconnect, SshUnimplemented
from cryptolyzer.ssh.ciphers import AnalyzerCiphers
from cryptoparser.ssh.subprotocol import SshKexAlgorithmVector, SshKexDHGexGroup


class AnalyzerResultDHParams(AnalyzerResultBase):
    def __init__(self, dhparams):
        self.dhparams = dhparams


class AnalyzerDHParams(AnalyzerSshBase):
    @classmethod
    def get_name(cls):
        return 'dhparams'

    @classmethod
    def get_help(cls):
        return 'Check DH parameters offered by the server(s)'

    def analyze(self, l7_client):
        ciphers_result = AnalyzerCiphers().analyze(l7_client)
        dhe_kex_algorithms = filter(
            lambda kex: kex.value.kex == KeyExchange.DHE and kex.value.key_size is None,
            ciphers_result.kex_algorithms
        )
        if not dhe_kex_algorithms:
            return AnalyzerResultDHParams([])

        dhparams = []
        key_exchange_init_message = SshKeyExchangeInitAnyAlgorithm()
        key_exchange_init_message.kex_algorithms = SshKexAlgorithmVector(dhe_kex_algorithms)

        for dh_key_size in [511, 1023, 1535, 2047, 3071, 4095, 6143, 7679, 8191]:
            dh_public_keys = []
            for j in range(2):
                try:
                    server_messages = l7_client.do_handshake(
                        key_exchange_init_message=key_exchange_init_message,
                        last_message_type=SshKexDHGexGroup,
                        dh_key_size=dh_key_size
                    )
                    kex_dh_gex_group_message = server_messages[SshKexDHGexGroup.get_message_code()]
                except NetworkError as e:
                    if e.error == NetworkErrorType.NO_RESPONSE:
                        break
                    else:
                        raise e
                except SshDisconnect:
                    continue
                except SshUnimplemented:
                    continue

                p_len = len(kex_dh_gex_group_message.p)
                if kex_dh_gex_group_message.p[0] == 0:
                    p_len -= 1
                if p_len * 8 != dh_key_size + 1:
                    continue

                p = int.from_bytes(kex_dh_gex_group_message.p, byteorder='big')
                g = int.from_bytes(kex_dh_gex_group_message.g, byteorder='big')

                parameter_numbers = cryptography_dh.DHParameterNumbers(p, g)
                public_numbers = cryptography_dh.DHPublicNumbers(j, parameter_numbers)
                dh_public_key = public_numbers.public_key(cryptography_default_backend())
                dh_public_keys.append(dh_public_key)
           
                if len(dh_public_keys) == 2:
                    dhparams.append(DHParameter(
                        dh_public_keys[0],
                        dh_public_keys[0] == dh_public_keys[1],
                    ))

        return AnalyzerResultDHParams(dhparams)
