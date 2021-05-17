# -*- coding: utf-8 -*-

import unittest

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import requests
import urllib3

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerTargetHttp

from cryptolyzer.httpx.client import L7ClientHttp, L7ClientHttps


class TestHttpClient(unittest.TestCase):
    def test_error_unknown_scheme(self):
        with self.assertRaises(ValueError) as context_manager:
            L7ClientHttp.from_uri(urllib3.util.parse_url('unknown://mock.site'))
        self.assertEqual(context_manager.exception.args, ('unknown', ))

    @patch.object(requests, 'head', side_effect=requests.exceptions.ConnectionError)
    def test_error_connection_error(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            L7ClientHttp(urllib3.util.parse_url('http://mock.site')).do_handshake()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @patch.object(requests, 'head', side_effect=requests.exceptions.Timeout)
    def test_error_connection_timeout(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            L7ClientHttp(urllib3.util.parse_url('http://mock.site')).do_handshake()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @patch.object(requests, 'head', side_effect=requests.exceptions.HTTPError)
    def test_error_http_error(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            L7ClientHttp(urllib3.util.parse_url('http://mock.site')).do_handshake()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)

    @patch.object(requests, 'head', side_effect=requests.exceptions.TooManyRedirects)
    def test_error_too_many_redirects(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            L7ClientHttp(urllib3.util.parse_url('http://mock.site')).do_handshake()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)

    def test_client_port(self):
        l7_client = L7ClientHttp.from_uri(urllib3.util.parse_url('http://mock.site'))
        target = AnalyzerTargetHttp.from_l7_client(l7_client)
        self.assertEqual(target.port, 80)

        l7_client = L7ClientHttp.from_uri(urllib3.util.parse_url('http://mock.site:81'))
        target = AnalyzerTargetHttp.from_l7_client(l7_client)
        self.assertEqual(target.port, 81)

    @patch('requests.head', return_value=requests.Response())
    def test_client_http(self, mock_response):
        mock_response.return_value.headers = {'X-Test-Header-Name': 'Value'}
        headers = L7ClientHttp(urllib3.util.parse_url('http://mock.site')).do_handshake()
        self.assertEqual(b'X-Test-Header-Name: Value\r\n\r\n', headers)

    @patch('requests.head', return_value=requests.Response())
    def test_client_https(self, mock_response):
        mock_response.return_value.headers = {'X-Test-Header-Name': 'Value'}
        headers = L7ClientHttps(urllib3.util.parse_url('https://mock.site')).do_handshake()
        self.assertEqual(b'X-Test-Header-Name: Value\r\n\r\n', headers)
