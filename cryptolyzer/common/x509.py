# -*- coding: utf-8 -*-

import collections

import asn1crypto

from cryptodatahub.common.key import PublicKeyX509Base

from cryptoparser.common.x509 import SignedCertificateTimestampList


class PublicKeyX509(PublicKeyX509Base):
    @property
    def signed_certificate_timestamps(self):
        for extension in self._certificate['tbs_certificate']['extensions']:
            if extension['extn_id'].dotted == '1.3.6.1.4.1.11129.2.4.2':
                asn1_value = asn1crypto.core.load(bytes(extension['extn_value']))
                return SignedCertificateTimestampList.parse_exact_size(bytes(asn1_value))

        return SignedCertificateTimestampList([])

    def _asdict(self):
        return collections.OrderedDict([
            ('serial_number', str(self.serial_number)),
            ('subject', self.subject),
            ('subject_alternative_names', sorted(self.subject_alternative_names)),
            ('issuer', self.issuer),
            ('key_type', self.key_type),
            ('key_size', self.key_size),
            ('signature_hash_algorithm', self.signature_hash_algorithm),
            ('extended_validation', self.extended_validation),
            ('validity', collections.OrderedDict([
                ('not_before', str(self.valid_not_before)),
                ('not_after', str(self.valid_not_after)),
                ('period', str(self.validity_period)),
                ('remaining', str(self.validity_remaining_time.days) if self.validity_remaining_time else None),
            ])),
            ('revocation', collections.OrderedDict([
                ('crl_distribution_points', self.crl_distribution_points),
                ('ocsp_responders', self.ocsp_responders),
            ])),
            ('signed_certificate_timestamps', self.signed_certificate_timestamps),
            ('fingerprints', self.fingerprints),
            ('public_key_pin', self.public_key_pin),
            ('version', self._certificate['tbs_certificate']['version'].native),
        ])
