# -*- coding: utf-8 -*-

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from test.common.classes import (
    TestLoggerBase,
    TestThreadedServerHttp,
    TestThreadedServerHttps,
    TestThreadedServerHttpProxy,
)

import requests
import urllib3

from cryptoparser.httpx.version import HttpVersion
from cryptoparser.httpx.header import HttpHeaderFieldServer, HttpHeaderFieldUnparsed

from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.httpx.client import L7ClientHttpBase
from cryptolyzer.httpx.headers import AnalyzerHeaders
from cryptolyzer.httpx.transfer import HttpHandshakeBase


class TestHttpHeaders(TestLoggerBase):
    @classmethod
    def get_result(cls, uri, l4_socket_params=L4TransferSocketParams()):
        analyzer = AnalyzerHeaders()
        client = L7ClientHttpBase.from_uri(urllib3.util.parse_url(uri))
        if l4_socket_params.timeout:
            client.timeout = l4_socket_params.timeout
        return analyzer.analyze(client, HttpVersion.HTTP1_1)

    @patch('requests.head', return_value=requests.Response())
    def test_http(self, mock_response):
        mock_response.return_value.headers = {'X-Test-Header-Name': 'Value'}
        analyzer_result = self.get_result('http://mock.site')
        self.assertEqual([HttpHeaderFieldUnparsed(name='X-Test-Header-Name', value='Value'), ], analyzer_result.headers)
        self.assertEqual(self.log_stream.getvalue(), 'Server offers headers X-Test-Header-Name\n')

    @patch('requests.head', return_value=requests.Response())
    def test_https(self, mock_response):
        mock_response.return_value.headers = {'X-Test-Header-Name': 'Value'}
        analyzer_result = self.get_result('https://mock.site')
        self.assertEqual([HttpHeaderFieldUnparsed(name='X-Test-Header-Name', value='Value'), ], analyzer_result.headers)
        self.assertEqual(self.log_stream.getvalue(), 'Server offers headers X-Test-Header-Name\n')

    @patch.object(
        HttpHandshakeBase, '_get_verify_path',
        return_value=str(TestThreadedServerHttps.CA_CERT_FILE_PATH)
    )
    def test_real(self, _):
        test_http_server = TestThreadedServerHttp('127.0.0.1', 0)
        test_http_server.init_connection()
        test_http_server.start()

        analyzer_result = self.get_result(f'http://127.0.0.1:{test_http_server.bind_port}')
        self.assertIn(HttpHeaderFieldServer('TestHTTPRequestHandler'), analyzer_result.headers)

        test_https_server = TestThreadedServerHttps('127.0.0.1', 0)
        test_https_server.init_connection()
        test_https_server.start()

        analyzer_result = self.get_result(f'https://127.0.0.1:{test_https_server.bind_port}')
        self.assertIn(HttpHeaderFieldServer('TestHTTPRequestHandler'), analyzer_result.headers)

        test_http_proxy_server = TestThreadedServerHttpProxy('127.0.0.2', 0)
        test_http_proxy_server.init_connection()
        test_http_proxy_server.start()

        http_proxy_url = urllib3.util.parse_url(f'http://127.0.0.2:{test_http_proxy_server.bind_port}')
        analyzer_result = self.get_result(
            f'http://127.0.0.1:{test_http_server.bind_port}',
            l4_socket_params=L4TransferSocketParams(http_proxy=http_proxy_url)
        )
        self.assertIn(HttpHeaderFieldServer('TestHTTPRequestHandler'), analyzer_result.headers)

        test_http_proxy_server.kill()
        test_http_server.kill()
        test_https_server.kill()
