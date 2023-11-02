# -*- coding: utf-8 -*-

import collections

import attr

import asn1crypto
import certvalidator

from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.entity import Entity, EntityRole
from cryptodatahub.common.stores import RootCertificate
from cryptodatahub.common.utils import bytes_to_hex_string

from cryptoparser.common.base import Serializable
from cryptoparser.common.x509 import PublicKeyX509


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
class CertificateChainX509(object):
    items = attr.ib(
        init=False,
        default=[],
        validator=attr.validators.deep_iterable(attr.validators.instance_of(PublicKeyX509)),
    )
    revoked = attr.ib(
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
    ordered = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )
    contains_anchor = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bool))
    )


@attr.s
class CertificateChainX509Validator(object):  # pylint: disable=too-few-public-methods
    _validated = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(CertificateChainX509)),
    )

    @staticmethod
    def _get_asn1crypto_certificate(public_key):
        return public_key._certificate  # pylint: disable=protected-access

    def build_path(self, items):
        extra_trust_roots = [
            self._get_asn1crypto_certificate(item)
            for item in items
            if item.is_self_signed
        ]
        intermediate_certs = [
            self._get_asn1crypto_certificate(item)
            for item in items
            if item.is_ca and not item.is_self_signed
        ]
        end_entity_certs = [
            self._get_asn1crypto_certificate(item)
            for item in items
            if not item.is_ca
        ]

        context = certvalidator.context.ValidationContext(
            extra_trust_roots=extra_trust_roots,
            weak_hash_algos=set(),
            whitelisted_certs=[item.fingerprints[Hash.SHA1] for item in items],
        )
        cert_validator = certvalidator.CertificateValidator(
            end_entity_cert=end_entity_certs[0],
            intermediate_certs=intermediate_certs,
            validation_context=context,
        )
        try:
            build_path = cert_validator.validate_usage(set())
        except (certvalidator.errors.PathBuildingError, certvalidator.errors.PathValidationError):
            self._validated.items = items
        else:
            self._validated.items = [PublicKeyX509(item) for item in reversed(build_path)]
            self._validated.contains_anchor = len(items) == len(self._validated.items)
            checkable_item_num = len(items)
            if self._validated.contains_anchor:
                checkable_item_num -= 1
            self._validated.ordered = self._validated.items[:checkable_item_num] == items[:checkable_item_num]
            items = self._validated.items

    def validate(self):
        trust_roots = []
        asn1crypto_certificates = list(map(self._get_asn1crypto_certificate, self._validated.items))

        for trust_store_owner in Entity.get_items_by_role(EntityRole.CA_TRUST_STORE_OWNER):
            context = certvalidator.context.ValidationContext(
                weak_hash_algos=set(),
                whitelisted_certs=[item.fingerprints[Hash.SHA1] for item in self._validated.items],
                trust_roots=list(map(
                    lambda root_certificate: self._get_asn1crypto_certificate(root_certificate.value.certificate),
                    RootCertificate.get_items_by_trust_owner(trust_store_owner),
                ))
            )
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

        self._validated.trust_roots = collections.OrderedDict(trust_roots)

    def check_revocation(self, certificate_status_list):
        context = certvalidator.context.ValidationContext(
            trust_roots=[],
            extra_trust_roots=[self._get_asn1crypto_certificate(self._validated.items[-1])],
            weak_hash_algos=set(),
            whitelisted_certs=[item.fingerprints[Hash.SHA1] for item in self._validated.items],
            ocsps=[certificate_status.ocsp_response for certificate_status in certificate_status_list],
            allow_fetching=True,
        )
        # NOTE: necessary only because of asn1crypto issue 262
        context._fetched_ocsps = {  # pylint: disable=protected-access
            self._get_asn1crypto_certificate(item).issuer_serial: []
            for item in self._validated.items
        }
        asn1crypto_certificates = list(map(self._get_asn1crypto_certificate, self._validated.items))
        cert_validator = certvalidator.CertificateValidator(
            end_entity_cert=asn1crypto_certificates[0],
            intermediate_certs=asn1crypto_certificates[1:],
            validation_context=context,
        )
        try:
            cert_validator.validate_usage(set())
        except certvalidator.errors.RevokedError:
            self._validated.revoked = True
        except (certvalidator.errors.PathBuildingError, certvalidator.errors.PathValidationError):
            pass
        else:
            self._validated.revoked = False

    def __call__(self, items, certificate_status_list=()):
        self._validated = CertificateChainX509()

        self.build_path(items)
        if self._validated.items:
            self.validate()
            self.check_revocation(certificate_status_list)

        return self._validated
