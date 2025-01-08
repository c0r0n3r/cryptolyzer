# -*- coding: utf-8 -*-

import abc
import urllib3

import attr


from cryptodatahub.common.types import convert_url

from cryptoparser.common.utils import get_leaf_classes

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.httpx.transfer import HttpHandshakeBase


@attr.s
class L7ClientHttpBase():
    uri = attr.ib(
        converter=convert_url(),
        validator=attr.validators.instance_of(urllib3.util.url.Url)
    )
    l4_socket_params = attr.ib(
        default=L4TransferSocketParams(),
        validator=attr.validators.instance_of(L4TransferSocketParams),
    )

    def __attrs_post_init__(self):
        if self.l4_socket_params.timeout is None:
            self.l4_socket_params = L4TransferSocketParams(
                self.get_default_timeout(), self.l4_socket_params.http_proxy
            )

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
            raise ValueError(uri.scheme) from e

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
        http_client = HttpClientHandshake(self.l4_socket_params)

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
        http_client = HttpsClientHandshake(self.l4_socket_params)

        http_client.do_handshake(self)

        return http_client.raw_headers


class HttpClientHandshake(HttpHandshakeBase):
    pass


class HttpsClientHandshake(HttpHandshakeBase):
    pass
