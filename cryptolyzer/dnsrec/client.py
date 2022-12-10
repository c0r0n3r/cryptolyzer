# -*- coding: utf-8 -*-

import abc

import attr
import urllib3

import six

from cryptodatahub.common.types import convert_url

from cryptoparser.common.utils import get_leaf_classes

from cryptolyzer.dnsrec.transfer import DnsHandshakeBase


@attr.s
class L7ClientDnsBase(object):
    domain = attr.ib(
        converter=convert_url(),
        validator=attr.validators.instance_of(urllib3.util.url.Url)
    )
    timeout = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of((float, int))))

    def __attrs_post_init__(self):
        if self.timeout is None:
            self.timeout = self.get_default_timeout()

    @classmethod
    def get_default_timeout(cls):
        return 5

    @classmethod
    def from_uri(cls, uri):
        try:
            transfer = next(iter(filter(
                lambda transfer_class: transfer_class.get_scheme() == uri.scheme,
                get_leaf_classes(cls)
            )))(uri)
        except StopIteration as e:
            six.raise_from(ValueError(uri.scheme), e)

        return transfer

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_supported_schemes(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_client_handshake_class(cls):
        raise NotImplementedError()


class L7ClientDns(L7ClientDnsBase):
    @classmethod
    def get_scheme(cls):
        return 'dns'

    @classmethod
    def get_supported_schemes(cls):
        return {'dns': L7ClientDns}

    @classmethod
    def get_client_handshake_class(cls):
        return DnsClientHandshake


class DnsClientHandshake(DnsHandshakeBase):
    pass
