# -*- coding: utf-8 -*-

from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.dhparam import parse_dh_params, DHParameter
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, ResponseError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloKeyExchangeDHE, TlsAlert


class AnalyzerResultDHParams(AnalyzerResultTls):
    def __init__(self, target, dhparams):
        super(AnalyzerResultDHParams, self).__init__(target)

        self.dhparams = dhparams


class AnalyzerDHParams(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'dhparams'

    @classmethod
    def get_help(cls):
        return 'Check DH parameters offered by the server(s)'

    def analyze(self, l7_client, protocol_version):
        client_hello = TlsHandshakeClientHelloKeyExchangeDHE(protocol_version, l7_client.address)

        dhparams = []
        dh_public_keys = []
        for _ in (1, 2):
            try:
                server_messages = l7_client.do_tls_handshake(
                    client_hello,
                    last_handshake_message_type=TlsHandshakeType.SERVER_KEY_EXCHANGE
                )
            except TlsAlert as e:
                acceptable_alerts = [
                    TlsAlertDescription.HANDSHAKE_FAILURE,
                    TlsAlertDescription.INTERNAL_ERROR,
                    TlsAlertDescription.INSUFFICIENT_SECURITY,
                    TlsAlertDescription.UNRECOGNIZED_NAME
                ]
                if e.description not in acceptable_alerts:
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            except ResponseError:
                break
            else:
                server_key_exchange_message = server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE]
                dh_public_key = parse_dh_params(server_key_exchange_message.param_bytes)
                dh_public_keys.append(dh_public_key)

                if len(dh_public_keys) == 2:
                    dhparams.append(DHParameter(
                        dh_public_keys[0],
                        dh_public_keys[0].public_numbers().y == dh_public_keys[1].public_numbers(),
                    ))

        return AnalyzerResultDHParams(
            AnalyzerTargetTls.from_l7_client(l7_client, protocol_version),
            dhparams
        )
