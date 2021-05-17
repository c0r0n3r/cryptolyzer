# -*- coding: utf-8 -*-

import unittest
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import requests
import urllib3

from cryptoparser.httpx.version import HttpVersion
from cryptoparser.httpx.header import HttpHeaderFieldUnparsed

from cryptolyzer.httpx.client import L7ClientHttpBase
from cryptolyzer.httpx.headers import AnalyzerHeaders


class TestHttpHeaders(unittest.TestCase):
    @classmethod
    def get_result(cls, uri):
        analyzer = AnalyzerHeaders()
        client = L7ClientHttpBase.from_uri(urllib3.util.parse_url(uri))
        return analyzer.analyze(client, HttpVersion.HTTP1_1)

    @patch('requests.head', return_value=requests.Response())
    def test_http(self, mock_response):
        mock_response.return_value.headers = {'X-Test-Header-Name': 'Value'}
        analyzer_result = self.get_result('http://mock.site')
        self.assertEqual([HttpHeaderFieldUnparsed(name='X-Test-Header-Name', value='Value'), ], analyzer_result.headers)

    @patch('requests.head', return_value=requests.Response())
    def test_https(self, mock_response):
        mock_response.return_value.headers = {'X-Test-Header-Name': 'Value'}
        analyzer_result = self.get_result('https://mock.site')
        self.assertEqual([HttpHeaderFieldUnparsed(name='X-Test-Header-Name', value='Value'), ], analyzer_result.headers)

    def test_real(self):
        analyzer_result = self.get_result('http://httpbin.org/response-headers?X-Test-Header-Name=Value')
        self.assertIn(HttpHeaderFieldUnparsed(name='X-Test-Header-Name', value='Value'), analyzer_result.headers)

        analyzer_result = self.get_result('https://httpbin.org/response-headers?X-Test-Header-Name=Value')
        self.assertIn(HttpHeaderFieldUnparsed(name='X-Test-Header-Name', value='Value'), analyzer_result.headers)
