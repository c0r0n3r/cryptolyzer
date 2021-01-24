# -*- coding: utf-8 -*-

import attr

from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.dhparam import parse_dh_params, DHParameter
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloKeyExchangeDHE
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultDHParams(AnalyzerResultTls):
    dhparams = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(DHParameter)),
        metadata={'human_readable_name': 'Diffie-Hellman Parameters'}
    )


class AnalyzerDHParams(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'dhparams'

    @classmethod
    def get_help(cls):
        return 'Check whether DH parameters are offered by the server(s)'

    def analyze(self, analyzable, protocol_version):
        client_hello = TlsHandshakeClientHelloKeyExchangeDHE(protocol_version, analyzable.address)

        dhparams = []
        dh_public_keys = []
        for _ in (1, 2):
            try:
                server_messages = analyzable.do_tls_handshake(
                    client_hello,
                    last_handshake_message_type=TlsHandshakeType.SERVER_KEY_EXCHANGE
                )
            except TlsAlert as e:
                if (e.description not in AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS + [
                       TlsAlertDescription.UNRECOGNIZED_NAME, ]):
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            except SecurityError:
                break
            else:
                server_key_exchange_message = server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE]
                dh_public_key = parse_dh_params(server_key_exchange_message.param_bytes)
                dh_public_keys.append(dh_public_key)

                if len(dh_public_keys) == 2:
                    dhparams.append(DHParameter(
                        dh_public_keys[0],
                        dh_public_keys[0].public_numbers.y == dh_public_keys[1].public_numbers.y,
                    ))

        return AnalyzerResultDHParams(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            dhparams
        )
