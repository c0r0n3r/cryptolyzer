# -*- coding: utf-8 -*-

import collections

import attr

import asn1crypto
import certvalidator

from cryptodatahub.common.entity import Entity, EntityRole
from cryptodatahub.common.key import PublicKeyX509Base
from cryptodatahub.common.stores import RootCertificate
from cryptodatahub.common.utils import bytes_to_hex_string

from cryptoparser.common.base import Serializable
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
        items = [
            ('version', self._certificate['tbs_certificate']['version'].native),
            ('serial_number', str(self.serial_number)),
            ('subject', self.subject),
            ('subject_alternative_names', sorted(self.subject_alternative_names)),
            ('issuer', self.issuer),
            ('key_type', self.key_type),
            ('key_size', self.key_size),
            ('signature_hash_algorithm', self.signature_hash_algorithm),
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
        ]

        if not self.is_ca:
            items += [
                ('end_entity', collections.OrderedDict([
                    ('extended_validation', self.extended_validation),
                    ('tls_features', list(map(lambda feature: feature.name, self.tls_features))),
                ]))
            ]

        return collections.OrderedDict(items)


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

        return bytes_to_hex_string(bytes(self._response_data['responder_id'].chosen), ':')

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

    @property
    def extensions(self):
        return [
            extension['extn_id'].dotted
            for extension in self._response['single_extensions']
        ]

    def _asdict(self):
        if self.ocsp_response is None:
            return collections.OrderedDict()

        return collections.OrderedDict([
           ('status', self.status),
           ('responder', self.responder),
           ('produced_at', str(self.produced_at)),
           ('this_update', str(self.this_update)),
           ('next_update', str(self.next_update)),
           ('update_interval', str(self.update_interval)),
           ('revocation_time', str(self.revocation_time)),
           ('revocation_time', self.revocation_reason),
           ('extensions', self.extensions),
        ])


@attr.s
class CertificateChainX509(Serializable):  # pylint: disable=too-few-public-methods
    items = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(PublicKeyX509)),
        metadata={'human_readable_name': 'Certificates in Chain'},
    )
    ordered = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )
    trust_roots = attr.ib(
        init=False,
        default=collections.OrderedDict([]),
        validator=attr.validators.deep_mapping(
            key_validator=attr.validators.instance_of(Entity),
            value_validator=attr.validators.instance_of(bool),
        )
    )
    contains_anchor = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )

    @staticmethod
    def _get_asn1crypto_certificate(public_key):
        return public_key._certificate  # pylint: disable=protected-access

    def build_path(self):
        asn1crypto_certificates = list(map(self._get_asn1crypto_certificate, self.items))
        cert_validator = certvalidator.CertificateValidator(asn1crypto_certificates[0], asn1crypto_certificates[1:])
        try:
            build_path = cert_validator.validate_usage(set())
        except certvalidator.errors.PathBuildingError:
            pass
        except (certvalidator.errors.InvalidCertificateError, certvalidator.errors.PathValidationError):
            if self.items[-1].is_self_signed:
                self.contains_anchor = True
        else:
            validated_items = [PublicKeyX509(item) for item in reversed(build_path)]
            self.contains_anchor = len(self.items) == len(validated_items)
            checkable_item_num = len(self.items)
            if self.contains_anchor:
                checkable_item_num -= 1
            self.ordered = validated_items[:checkable_item_num] = self.items[:checkable_item_num]
            self.items = validated_items

    def validate(self):
        trust_roots = []
        asn1crypto_certificates = list(map(self._get_asn1crypto_certificate, self.items))

        for trust_store_owner in Entity.get_items_by_role(EntityRole.CA_TRUST_STORE_OWNER):
            context = certvalidator.context.ValidationContext(trust_roots=list(map(
                lambda root_certificate: self._get_asn1crypto_certificate(root_certificate.value.certificate),
                RootCertificate.get_items_by_trust_owner(trust_store_owner),
            )))
            cert_validator = certvalidator.CertificateValidator(
                end_entity_cert=asn1crypto_certificates[0],
                intermediate_certs=asn1crypto_certificates[1:],
                validation_context=context,
            )
            try:
                cert_validator.validate_usage(set())
            except (certvalidator.errors.PathBuildingError, certvalidator.errors.PathValidationError):
                trust_roots.append((trust_store_owner, False))
            else:
                trust_roots.append((trust_store_owner, True))

        self.trust_roots = collections.OrderedDict(trust_roots)

    def __attrs_post_init__(self):
        self.build_path()
        self.validate()
