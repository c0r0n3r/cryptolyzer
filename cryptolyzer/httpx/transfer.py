# -*- coding: utf-8 -*-

import attr
import requests
import six

from cryptolyzer.common.exception import NetworkError, NetworkErrorType


@attr.s
class HttpHandshakeBase(object):
    timeout = attr.ib(validator=attr.validators.instance_of((float, int)))
    response = attr.ib(init=False, validator=attr.validators.instance_of(requests.Response))

    @classmethod
    def _get_verify_path(cls):
        return None  # use default verify path

    @property
    def raw_headers(self):
        raw_headers = '\r\n'.join([
            '{}: {}'.format(name, value)
            for name, value in self.response.headers.items()
        ]) + '\r\n'

        if len(self.response.headers) == 1:
            raw_headers += '\r\n'

        return raw_headers.encode('ascii')

    def do_handshake(self, transfer):
        try:
            self.response = requests.head(transfer.uri, verify=self._get_verify_path(), timeout=self.timeout)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)
        except requests.exceptions.HTTPError as e:
            # HTTP request returned an unsuccessful status code
            six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)
        except requests.exceptions.TooManyRedirects as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)
