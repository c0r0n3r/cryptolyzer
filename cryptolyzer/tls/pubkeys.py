#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import OrderedDict

import cryptography
import cryptography.x509 as cryptography_x509
import cryptography.x509.ocsp as cryptography_ocsp
import cryptography.hazmat.primitives.asymmetric.rsa as cryptography_rsa
import cryptography.hazmat.primitives.asymmetric.ec as cryptography_ec

from cryptography.hazmat.backends import default_backend as cryptography_default_backend
from cryptography.hazmat.primitives.asymmetric import padding as cryptography_padding

from cryptoparser.common.base import JSONSerializable
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription, TlsCipherSuiteVector
from cryptoparser.tls.extension import TlsExtensionType
from cryptoparser.tls.extension import TlsExtensionCertificateStatusRequest, TlsCertificateStatusType
from cryptoparser.tls.extension import TlsExtensionSignedCertificateTimestamp, SignedCertificateTimestampVector

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.tls.client import TlsAlert, \
    TlsHandshakeClientHelloAuthenticationDSS, \
    TlsHandshakeClientHelloAuthenticationRSA, \
    TlsHandshakeClientHelloAuthenticationECDSA

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultTls
import cryptolyzer.common.utils as utils
import cryptolyzer.common.x509 as x509


class TlsCertificateChain(JSONSerializable):  # pylint: disable=too-few-public-methods
    def __init__(self, certificate_bytes, certificate_chain):
        self._certificate_bytes = certificate_bytes
        self.items = certificate_chain
        self.verified = None

        ordered_certificate_chain = [cert for cert in certificate_chain if not cert.is_ca]
        self.complete = len(ordered_certificate_chain) == 1

        while len(ordered_certificate_chain) <= len(self.items):
            try:
                next_certificate = self.next_issuer(ordered_certificate_chain[-1].issuer)
                ordered_certificate_chain.append(next_certificate)
            except StopIteration:
                break

        if self.complete:
            self.ordered = self.items == ordered_certificate_chain
            self.items = ordered_certificate_chain

            self.verified = False
            for chain_index in range(len(self.items) - 1):
                issuer_public_key = self.items[chain_index + 1].public_key()
                cert_to_check = self.items[chain_index]

                if not self._is_signed_verifiable(issuer_public_key, cert_to_check):
                    break
            else:
                self.verified = True


    def __hash__(self):
        return hash(tuple([bytes(certificate_byte) for certificate_byte in self._certificate_bytes]))

    def __eq__(self, other):
        return hash(self) == hash(other)

    @staticmethod
    def _is_signed_verifiable(issuer_public_key, cert_to_check):
        verify_args = {
            'signature': cert_to_check.signature,
            'data': cert_to_check.tbs_certificate_bytes,
        }
        if isinstance(issuer_public_key, cryptography_rsa.RSAPublicKey):
            verify_args['padding'] = cryptography_padding.PKCS1v15()
        if isinstance(issuer_public_key, cryptography_ec.EllipticCurvePublicKey):
            verify_args['signature_algorithm'] = cryptography_ec.ECDSA(
                    cert_to_check._certificate.signature_hash_algorithm
            )
        else:
            verify_args['algorithm'] = cert_to_check._certificate.signature_hash_algorithm

        try:
            issuer_public_key.verify(**verify_args)
        except cryptography.exceptions.InvalidSignature:
             return False

        return True

    def next_issuer(self, issuer):
        next_certificates = [
            certificate
            for certificate in self.items
            if certificate.is_ca and certificate.subject == issuer
        ]
        if len(next_certificates) == 1:
            return next_certificates[0]

        raise StopIteration()

    @property
    def contains_anchor(self):
        return any([cert.is_self_signed for cert in self.items])

    def as_json(self):
        return OrderedDict([
            ('items_chain', self.items),
            ('complete', self.complete),
            ('ordered', self.ordered),
            ('verified', self.verified),
            ('contains_anchor', self.contains_anchor),
        ])


class CertificateStatus(JSONSerializable):
    def __init__(self, ocsp_response):
        self.ocsp_response = ocsp_response

    @property
    def scts(self):
        try:
            extension = self.ocsp_response.single_extensions.get_extension_for_class(
                cryptography_x509.SignedCertificateTimestamps
            )
        except cryptography_x509.ExtensionNotFound:
            return []
        else:
            return [x509.SignedCertificateTimestamp(sct) for sct in list(extension.value)]

    def as_json(self):
        if self.ocsp_response is None:
            return OrderedDict()
        if self.ocsp_response.response_status != cryptography_ocsp.OCSPResponseStatus.SUCCESSFUL:
            return OrderedDict()

        cert_status = self.ocsp_response.certificate_status
        return OrderedDict([
            ('status', cert_status.name.lower()),
            ('responder', 
                self.ocsp_response.responder_name.rfc4514_string()
                if self.ocsp_response.responder_name
                else utils.bytes_to_colon_separated_hex(self.ocsp_response.responder_key_hash)
            ),
            ('produced_at', str(self.ocsp_response.produced_at)),
            ('this_update', str(self.ocsp_response.this_update)),
            ('next_update', str(self.ocsp_response.next_update)),
            ('update_interval', str(self.ocsp_response.next_update - self.ocsp_response.this_update)),
            ('revocation_time',
                str(self.ocsp_response.revocation_time)
                if cert_status == cryptography_ocsp.OCSPCertStatus.REVOKED
                else None
            ),
            ('revocation_reason',
                str(self.ocsp_response.revocation_reason)
                if cert_status == cryptography_ocsp.OCSPCertStatus.REVOKED
                else None
            ),
            ('scts', self.scts),
        ])


class TlsPublicKey(JSONSerializable):  # pylint: disable=too-few-public-methods
    def __init__(self, certificate_bytes, certificate_chain, ocsp_response, scts):
        self.certificate_chain = TlsCertificateChain(certificate_bytes, certificate_chain)
        self.status = CertificateStatus(ocsp_response)
        self.scts = [x509.SignedCertificateTimestamp(sct) for sct in scts]

    def as_json(self):
        return OrderedDict([
            ('certificate_chain', self.certificate_chain),
            ('status', self.status),
            ('scts', self.scts),
        ])


class AnalyzerResultPublicKeys(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, pubkeys, host_name):
        self.host_name = host_name
        self.pubkeys = pubkeys


class AnalyzerPublicKeys(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'pubkeys'

    @classmethod
    def get_help(cls):
        return 'Check which certificate used by the server(s)'

    @staticmethod
    def _get_tls_public_key(server_messages, ocsp_response, scts):
        certificate_chain = []
        certificate_bytes = []

        for tls_certificate in server_messages[TlsHandshakeType.CERTIFICATE].certificate_chain:
            try:
                certificate = cryptography_x509.load_der_x509_certificate(
                    bytes(tls_certificate.certificate),
                    cryptography_default_backend()
                )
            except ValueError:
                pass
            else:
                certificate_bytes.append(tls_certificate.certificate)
                certificate_chain.append(x509.PublicKeyX509(certificate))

        return TlsPublicKey(
            certificate_bytes=certificate_bytes,
            certificate_chain=certificate_chain,
            ocsp_response=ocsp_response,
            scts=scts,
        )

    def analyze(self, l7_client, protocol_version):
        results = []
        client_hello_messages = [
            TlsHandshakeClientHelloBasic(),
            TlsHandshakeClientHelloAuthenticationDSS(l7_client.host),
            TlsHandshakeClientHelloAuthenticationRSA(l7_client.host),
            TlsHandshakeClientHelloAuthenticationECDSA(l7_client.host),
        ]
        accepted_client_hello_messages = []

        for client_hello in client_hello_messages:
            try:
                client_hello.protocol_version = protocol_version
                server_messages = l7_client.do_tls_handshake(
                    client_hello,
                    client_hello.protocol_version,
                    TlsHandshakeType.SERVER_HELLO
                )
            except TlsAlert as e:
                if (e.description != TlsAlertDescription.HANDSHAKE_FAILURE and
                        e.description != TlsAlertDescription.PROTOCOL_VERSION):
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            else:
                client_hello.cipher_suites = TlsCipherSuiteVector([
                    server_messages[TlsHandshakeType.SERVER_HELLO].cipher_suite,
                ])
                accepted_client_hello_messages.append(client_hello)

        for idx, client_hello in enumerate(accepted_client_hello_messages):
            client_hello.extensions.extend([
                TlsExtensionCertificateStatusRequest(),
                TlsExtensionSignedCertificateTimestamp([]),
            ])

            try:
                server_messages = l7_client.do_tls_handshake(
                    client_hello,
                    client_hello.protocol_version,
                    TlsHandshakeType.SERVER_HELLO_DONE
                )
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            else:
                ocsp_response = None
                if TlsHandshakeType.CERTIFICATE_STATUS in server_messages:
                    status_message = server_messages[TlsHandshakeType.CERTIFICATE_STATUS]
                    if status_message.status_type == TlsCertificateStatusType.OCSP:
                        ocsp_response = cryptography_ocsp.load_der_ocsp_response(status_message.status)

                signed_certificate_timestamps = []
                for extension in server_messages[TlsHandshakeType.SERVER_HELLO].extensions:
                    if extension.extension_type == TlsExtensionType.SIGNED_CERTIFICATE_TIMESTAMP:
                        signed_certificate_timestamps = extension.scts
                        break

                sni_sent = not isinstance(client_hello, TlsHandshakeClientHelloBasic)
                tls_public_key = self._get_tls_public_key(server_messages, ocsp_response, signed_certificate_timestamps)
                leaf_certificate = tls_public_key.certificate_chain.items[0]
                subject_matches = x509.is_subject_matches(
                    leaf_certificate.common_names,
                    leaf_certificate.subject_alternative_names,
                    l7_client.host
                )
                if ((not sni_sent and not subject_matches) or
                    tls_public_key.certificate_chain in [result['pubkey'] for result in results]):
                    continue

                results.append(OrderedDict([
                    ('sni_sent', sni_sent),
                    ('subject_matches', subject_matches),
                    ('pubkey', tls_public_key),
                ]))

        return AnalyzerResultPublicKeys(results, l7_client.host)
