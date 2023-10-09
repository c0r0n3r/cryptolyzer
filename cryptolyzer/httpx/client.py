# -*- coding: utf-8 -*-

import abc
import urllib3

import attr

import six

from cryptodatahub.common.types import convert_url

from cryptoparser.common.utils import get_leaf_classes

from cryptolyzer.httpx.transfer import HttpHandshakeBase


@attr.s
class L7ClientHttpBase(object):
    uri = attr.ib(
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
    def get_default_port(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_supported_schemes(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def do_handshake(self):
        raise NotImplementedError()


class L7ClientHttp(L7ClientHttpBase):
    @classmethod
    def get_scheme(cls):
        return 'http'

    @classmethod
    def get_default_port(cls):
        return 80

    @classmethod
    def get_supported_schemes(cls):
        return {'http': L7ClientHttp}

    def do_handshake(self):
        http_client = HttpClientHandshake(self.timeout)

        http_client.do_handshake(self)

        return http_client.raw_headers


class L7ClientHttps(L7ClientHttpBase):
    @classmethod
    def get_scheme(cls):
        return 'https'

    @classmethod
    def get_default_port(cls):
        return 443

    @classmethod
    def get_supported_schemes(cls):
        return {'https': L7ClientHttps}

    def do_handshake(self):
        http_client = HttpsClientHandshake(self.timeout)

        http_client.do_handshake(self)

        return http_client.raw_headers


class HttpClientHandshake(HttpHandshakeBase):
    pass


class HttpsClientHandshake(HttpHandshakeBase):
    pass
