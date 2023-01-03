# -*- coding: utf-8 -*-

import abc
import base64
import datetime

from collections import OrderedDict

import asn1crypto.x509
import attr

from cryptodatahub.common.algorithm import Authentication, Hash, Signature

import cryptoparser.common.key
import cryptoparser.common.utils
from cryptoparser.common.x509 import SignedCertificateTimestampList


class PublicKey(cryptoparser.common.key.PublicKey):
    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def valid_not_before(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def valid_not_after(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def validity_period(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def validity_remaining_time(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def signature_hash_algorithm(self):
        raise NotImplementedError()


@attr.s(eq=False)
class PublicKeyX509(PublicKey):  # pylint: disable=too-many-public-methods
    _EV_OIDS_BY_CA = {
        'A-Trust': ('1.2.40.0.17.1.22', ),
        'Actalis': ('1.3.159.1.17.1', ),
        'AffirmTrust': (
            '1.3.6.1.4.1.34697.2.1',
            '1.3.6.1.4.1.34697.2.2',
            '1.3.6.1.4.1.34697.2.3',
            '1.3.6.1.4.1.34697.2.4',
        ),
        'Buypass': ('2.16.578.1.26.1.3.3', ),
        'Camerfirma': (
            '1.3.6.1.4.1.17326.10.14.2.1.2',
            '1.3.6.1.4.1.17326.10.8.12.1.2',
        ),
        'Comodo Group': ('1.3.6.1.4.1.6449.1.2.1.5.1', ),
        'DigiCert': (
            '2.16.840.1.114412.1.3.0.2',
            '2.16.840.1.114412.2.1',
        ),
        'DigiNotar': ('2.16.528.1.1001.1.1.1.12.6.1.1.1', ),
        'E-Tugra': ('2.16.792.3.0.4.1.1.4', ),
        'ETSI': (
            '0.4.0.2042.1.4',
            '0.4.0.2042.1.5',
        ),
        'Entrust': ('2.16.840.1.114028.10.1.2', ),
        'Firmaprofesional': ('1.3.6.1.4.1.13177.10.1.3.10', ),
        'GeoTrust': ('1.3.6.1.4.1.14370.1.6', ),
        'GlobalSign': ('1.3.6.1.4.1.4146.1.1', ),
        'Go Daddy': ('2.16.840.1.114413.1.7.23.3', ),
        'Izenpe': ('1.3.6.1.4.1.14777.6.1.1', ),
        'Kamu Sertifikasyon Merkezi': ('2.16.792.1.2.1.1.5.7.1.9', ),
        'Logius PKIoverheid': ('2.16.528.1.1003.1.2.7', ),
        'Network Solutions': ('1.3.6.1.4.1.782.1.2.1.8.1', ),
        'OpenTrust/DocuSign France': ('1.3.6.1.4.1.22234.2.5.2.3.1', ),
        'QuoVadis': ('1.3.6.1.4.1.8024.0.2.100.1.2', ),
        'SECOM Trust Systems': ('1.2.392.200091.100.721.1', ),
        'SHECA': ('1.2.156.112570.1.1.3', ),
        'Starfield Technologies': ('2.16.840.1.114414.1.7.23.3', ),
        'StartCom Certification Authority': (
            '1.3.6.1.4.1.23223.1.1.1',
            '1.3.6.1.4.1.23223.2',
        ),
        'SwissSign': ('2.16.756.1.89.1.2.1.1', ),
        'Swisscom': ('2.16.756.1.83.21.0', ),
        'Symantec (VeriSign)': ('2.16.840.1.113733.1.7.23.6', ),
        'T-Systems': ('1.3.6.1.4.1.7879.13.24.1', ),
        'Thawte': ('2.16.840.1.113733.1.7.48.1', ),
        'Trustwave': ('2.16.840.1.114404.1.1.2.4.1', ),
        'Verizon Business (formerly Cybertrust)': ('1.3.6.1.4.1.6334.1.100.1', ),
        'Wells Fargo': ('2.16.840.1.114171.500.9', ),
        'WoSign': ('1.3.6.1.4.1.36305.2', ),
    }

    certificate = attr.ib(validator=attr.validators.instance_of(asn1crypto.x509.Certificate))

    @property
    def key_bytes(self):
        return self.certificate.dump()

    def __eq__(self, other):
        return self.key_bytes == other.key_bytes

    @property
    def valid_not_before(self):
        return self.certificate.not_valid_before

    @property
    def valid_not_after(self):
        return self.certificate.not_valid_after

    @property
    def expired(self):
        return datetime.datetime.now(asn1crypto.util.timezone.utc) > self.certificate.not_valid_after

    @property
    def validity_period(self):
        return self.certificate.not_valid_after - self.certificate.not_valid_before

    @property
    def validity_remaining_time(self):
        now = datetime.datetime.now(asn1crypto.util.timezone.utc)
        return self.certificate.not_valid_after - now if now < self.certificate.not_valid_after else None

    @property
    def key_type(self):
        try:
            subject_public_key_info = self.certificate['tbs_certificate']['subject_public_key_info']
            key_type_oid = subject_public_key_info['algorithm']['algorithm'].dotted
        except KeyError as e:
            key_type_oid = e.args[0]

        return Authentication.from_oid(key_type_oid)

    @property
    def key_size(self):
        if self.key_type == Authentication.GOST_R3410_12_256:
            return 256
        if self.key_type == Authentication.GOST_R3410_12_512:
            return 512
        if self.key_type == Authentication.GOST_R3410_01:
            return 256

        return int(self.certificate['tbs_certificate']['subject_public_key_info'].bit_size)

    @property
    def signature_hash_algorithm(self):
        try:
            signature_oid = self.certificate['signature_algorithm']['algorithm'].dotted
        except KeyError as e:
            signature_oid = e.args[0]

        return Signature.from_oid(signature_oid)

    @property
    def fingerprints(self):
        return OrderedDict([
            (
                hash_type,
                cryptoparser.common.utils.bytes_to_hex_string(self.get_digest(hash_type, self.key_bytes), ':')
            )
            for hash_type in [Hash.MD5, Hash.SHA1, Hash.SHA2_256]
        ])

    @property
    def public_key_pin(self):
        return base64.b64encode(self.get_digest(Hash.SHA2_256, self.certificate.public_key.dump())).decode('ascii')

    @property
    def extended_validation(self):
        if self.certificate.certificate_policies_value is None:
            return False

        for policy_information in self.certificate.certificate_policies_value:
            for ca_ev_oid_list in self._EV_OIDS_BY_CA.values():
                if policy_information['policy_identifier'].dotted in ca_ev_oid_list:
                    return True

        return False

    @property
    def subject(self):
        return self.certificate.subject.native

    @property
    def issuer(self):
        return self.certificate.issuer.native

    @property
    def valid_domains(self):
        return self.certificate.valid_domains

    def is_subject_matches(self, host_name):
        return self.certificate.is_valid_domain_ip(host_name)

    @property
    def subject_alternative_names(self):
        if self.certificate.subject_alt_name_value is None:
            return []

        return self.certificate.subject_alt_name_value.native

    @property
    def crl_distribution_points(self):
        if self.certificate.crl_distribution_points_value is None:
            return []

        return [
            crl_distribution_point.url
            for crl_distribution_point in self.certificate.crl_distribution_points_value
        ]

    @property
    def ocsp_responders(self):
        return self.certificate.ocsp_urls

    @property
    def signed_certificate_timestamps(self):
        for extension in self.certificate['tbs_certificate']['extensions']:
            if extension['extn_id'].dotted == '1.3.6.1.4.1.11129.2.4.2':
                asn1_value = asn1crypto.core.load(bytes(extension['extn_value']))
                return SignedCertificateTimestampList.parse_exact_size(bytes(asn1_value))

        return SignedCertificateTimestampList([])

    @property
    def is_ca(self):
        return self.certificate.ca

    @property
    def is_self_signed(self):
        return self.certificate.self_issued

    @classmethod
    def _markdown_human_readable_names(cls, obj, dict_value):
        name_dict = super(PublicKeyX509, cls)._markdown_human_readable_names(obj, dict_value)

        if 'crl_distribution_points' in name_dict:
            name_dict['crl_distribution_points'] = 'CRL Distribution Point'
        if 'ocsp_responders' in name_dict:
            name_dict['ocsp_responders'] = 'OCSP Responders'

        return name_dict

    def _asdict(self):
        return OrderedDict([
            ('serial_number', str(self.certificate.serial_number)),
            ('subject', self.subject),
            ('subject_alternative_names', sorted(self.subject_alternative_names)),
            ('issuer', self.issuer),
            ('key_type', self.key_type),
            ('key_size', self.key_size),
            ('signature_hash_algorithm', self.signature_hash_algorithm),
            ('extended_validation', self.extended_validation),
            ('validity', OrderedDict([
                ('not_before', str(self.valid_not_before)),
                ('not_after', str(self.valid_not_after)),
                ('period', str(self.validity_period)),
                ('remaining', str(self.validity_remaining_time.days) if self.validity_remaining_time else None),
            ])),
            ('revocation', OrderedDict([
                ('crl_distribution_points', self.crl_distribution_points),
                ('ocsp_responders', self.ocsp_responders),
            ])),
            ('signed_certificate_timestamps', self.signed_certificate_timestamps),
            ('fingerprints', self.fingerprints),
            ('public_key_pin', self.public_key_pin),
            ('version', self.certificate['tbs_certificate']['version'].native),
        ])
