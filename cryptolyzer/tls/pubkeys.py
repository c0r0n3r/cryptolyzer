# -*- coding: utf-8 -*-

from collections import OrderedDict

import attr

import six

import asn1crypto.ocsp
import asn1crypto.x509
import certvalidator

from cryptoparser.common.base import Serializable
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.extension import TlsExtensionCertificateStatusRequest, TlsCertificateStatusType

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloAuthenticationDSS,
    TlsHandshakeClientHelloAuthenticationRSA,
    TlsHandshakeClientHelloAuthenticationECDSA,
    TlsHandshakeClientHelloAuthenticationGOST,
)
from cryptolyzer.tls.exception import TlsAlert

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
import cryptolyzer.common.utils
import cryptolyzer.common.x509


@attr.s
class CertificateStatus(Serializable):
    ocsp_response = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(asn1crypto.ocsp.OCSPResponse))
    )

    @property
    def _response_data(self):
        return self.ocsp_response.basic_ocsp_response['tbs_response_data']

    @property
    def _response(self):
        return self._response_data['responses'][0]

    @property
    def status(self):
        cert_status = self._response['cert_status']
        return cert_status.name.lower()

    @property
    def responder(self):
        if self._response_data['responder_id'].name == 'by_name':
            return self._response_data['responder_id'].chosen.native

        return cryptolyzer.common.utils.bytes_to_colon_separated_hex(
            bytes(self._response_data['responder_id'].chosen)
        )

    @property
    def produced_at(self):
        return self._response_data['produced_at'].native

    @property
    def this_update(self):
        return self._response['this_update'].native

    @property
    def next_update(self):
        return self._response['next_update'].native

    @property
    def update_interval(self):
        return self.next_update - self.this_update

    @property
    def revocation_time(self):
        cert_status = self._response['cert_status']
        if cert_status.name != 'revoked':
            return None

        return cert_status.chosen['revocation_time'].native

    @property
    def revocation_reason(self):
        cert_status = self._response['cert_status']
        if cert_status.name != 'revoked':
            return None

        return cert_status.chosen['revocation_reason'].native

    def _asdict(self):
        if self.ocsp_response is None:
            return OrderedDict()

        return OrderedDict([
           ('status', self.status),
           ('responder', self.responder),
           ('produced_at', str(self.produced_at)),
           ('this_update', str(self.this_update)),
           ('next_update', str(self.next_update)),
           ('update_interval', str(self.update_interval)),
           ('revocation_time', str(self.revocation_time)),
           ('revocation_time', self.revocation_reason),
        ])


@attr.s
class TlsCertificateChain(Serializable):  # pylint: disable=too-few-public-methods
    items = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(cryptolyzer.common.x509.PublicKeyX509)),
        metadata={'human_readable_name': 'Certificates in Chain'},
    )
    ordered = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )
    verified = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )
    contains_anchor = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )

    def __attrs_post_init__(self):
        cert_validator = certvalidator.CertificateValidator(
            self.items[0].certificate,
            [item.certificate for item in self.items[1:]]
        )
        try:
            build_path = cert_validator.validate_usage(set())
        except certvalidator.errors.PathBuildingError:
            pass
        except (certvalidator.errors.InvalidCertificateError, certvalidator.errors.PathValidationError):
            if self.items[-1].is_self_signed:
                self.contains_anchor = True
        else:
            self.verified = True
            validated_items = [cryptolyzer.common.x509.PublicKeyX509(item) for item in reversed(build_path)]
            self.ordered = validated_items[:len(self.items)] == self.items
            self.contains_anchor = len(self.items) == len(validated_items)


@attr.s
class TlsPublicKey(Serializable):
    sni_sent = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Server Name Indication (SNI)'}
    )
    subject_matches = attr.ib(validator=attr.validators.instance_of(bool))
    tls_certificate_chain = attr.ib(
        validator=attr.validators.instance_of(TlsCertificateChain),
        metadata={'human_readable_name': 'Certificate Chain'}
    )
    certificate_status = attr.ib(
        default=None, eq=False,
        validator=attr.validators.optional(attr.validators.instance_of(CertificateStatus))
    )


@attr.s
class AnalyzerResultPublicKeys(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    pubkeys = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsPublicKey)),
        metadata={'human_readable_name': 'TLS Certificates'},
    )


class AnalyzerPublicKeys(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'pubkeys'

    @classmethod
    def get_help(cls):
        return 'Check which certificate used by the server(s)'

    @classmethod
    def _get_tls_certificate_chain(cls, server_messages):
        if TlsHandshakeType.CERTIFICATE not in server_messages:
            raise ValueError

        certificate_chain = []

        for tls_certificate in server_messages[TlsHandshakeType.CERTIFICATE].certificate_chain:
            certificate = asn1crypto.x509.Certificate.load(tls_certificate.certificate)
            certificate_chain.append(cryptolyzer.common.x509.PublicKeyX509(certificate))

        return TlsCertificateChain(items=certificate_chain)

    @classmethod
    def _add_tls_public_key_to_results(cls, analyzable, sni_sent, server_messages, results):
        try:
            certificate_chain = cls._get_tls_certificate_chain(server_messages)
        except ValueError:
            return

        leaf_certificate = certificate_chain.items[0]
        subject_matches = leaf_certificate.is_subject_matches(six.u(analyzable.address))
        if ((sni_sent or subject_matches) and
                certificate_chain not in [result.tls_certificate_chain for result in results]):
            tls_public_key_params = {
                'sni_sent': sni_sent,
                'subject_matches': subject_matches,
                'tls_certificate_chain': certificate_chain,
            }

            if TlsHandshakeType.CERTIFICATE_STATUS in server_messages:
                status_message = server_messages[TlsHandshakeType.CERTIFICATE_STATUS]
                if status_message.status_type == TlsCertificateStatusType.OCSP:
                    ocsp_response = asn1crypto.ocsp.OCSPResponse.load(bytes(status_message.status))
                    if ocsp_response['response_status'].native == 'successful':
                        certificate_status = CertificateStatus(
                            asn1crypto.ocsp.OCSPResponse.load(bytes(status_message.status))
                        )
                        tls_public_key_params['certificate_status'] = certificate_status

            results.append(TlsPublicKey(**tls_public_key_params))

    @staticmethod
    def _get_server_messages(l7_client, client_hello, sni_sent, client_hello_messages):
        server_messages = []

        try:
            server_messages = l7_client.do_tls_handshake(
                client_hello,
                last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
            )
        except TlsAlert as e:
            if e.description == TlsAlertDescription.UNRECOGNIZED_NAME:
                if sni_sent:
                    six.raise_from(StopIteration, e)
            elif e.description not in AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS + [
                    TlsAlertDescription.INTERNAL_ERROR,
                    TlsAlertDescription.DECODE_ERROR,
            ]:
                raise e
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e
        except SecurityError as e:
            if e.error != SecurityErrorType.UNPARSABLE_MESSAGE and client_hello == client_hello_messages[0]:
                six.raise_from(StopIteration, e)

        return server_messages

    def analyze(self, analyzable, protocol_version):
        results = []

        for hostname in [None, analyzable.address]:
            client_hello_messages = [
                TlsHandshakeClientHelloAuthenticationDSS(protocol_version, hostname),
                TlsHandshakeClientHelloAuthenticationRSA(protocol_version, hostname),
                TlsHandshakeClientHelloAuthenticationECDSA(protocol_version, hostname),
                TlsHandshakeClientHelloAuthenticationGOST(protocol_version, hostname),
            ]
            for client_hello in client_hello_messages:
                sni_sent = hostname is not None
                client_hello.extensions.extend([
                    TlsExtensionCertificateStatusRequest(),
                ])
                try:
                    server_messages = self._get_server_messages(
                        analyzable, client_hello, sni_sent, client_hello_messages
                    )
                except StopIteration:
                    break

                if not server_messages:
                    continue

                self._add_tls_public_key_to_results(analyzable, sni_sent, server_messages, results)

        return AnalyzerResultPublicKeys(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            results
        )
