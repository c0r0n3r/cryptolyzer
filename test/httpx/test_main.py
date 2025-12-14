# -*- coding: utf-8 -*-

from test.common.classes import TestMainBase, TestThreadedServerHttp

from cryptolyzer.__main__ import main


class TestMain(TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return main

    def test_header(self):
        test_http_server = TestThreadedServerHttp('127.0.0.1', 0)
        test_http_server.init_connection()
        test_http_server.start()

        uri = f'http://127.0.0.1:{test_http_server.bind_port}'

        result = self._get_test_analyzer_result_markdown('http', 'headers', uri)
        self.assertIn('Name: Server', result)
        self.assertIn('Value: TestHTTPRequestHandler', result)
        self.assertIn('Name: Date', result)
        self.assertIn('Value: 1970-01-01 00:00:00+00:00', result)

        result = self._get_test_analyzer_result_markdown('http1_1', 'headers', uri)
        self.assertIn('Name: Server', result)
        self.assertIn('Value: TestHTTPRequestHandler', result)
        self.assertIn('Name: Date', result)
        self.assertIn('Value: 1970-01-01 00:00:00+00:00', result)

        test_http_server.kill()

    def test_content(self):
        test_http_server = TestThreadedServerHttp('127.0.0.1', 0)
        test_http_server.init_connection()
        test_http_server.start()

        uri = f'http://127.0.0.1:{test_http_server.bind_port}'

        result = self._get_test_analyzer_result_markdown('http', 'content', uri + '/test/common/data/integrity.html')
        self.assertIn(
            'Source URL: '
            'https://static.cloudflareinsights.com/beacon.min.js/v84a3a4012de94ce1a686ba8c167c359c1696973893317',
            result
        )
        self.assertIn('Hash Algorithm: SHA-512', result)
        self.assertIn(
            'Hash Value: euoFGowhlaLqXsPWQ48qSkBSCFs3DPRyiwVu3FjR96cMPx+Fr+gpWRhIafcHwqwCqWS42RZhIudOvEI+Ckf6MA==',
            result
        )
        self.assertIn('Is Hash Correct: yes', result)

        result = self._get_test_analyzer_result_markdown(
            'http', 'content', uri + '/test/common/data/mixed-content.html'
        )
        self.assertIn('Data Type: script', result)
        self.assertIn('Source URL: http://example.com/script.js', result)

        test_http_server.kill()

    def test_default_scheme(self):
        uri = 'example.org'
        result = self._get_test_analyzer_result_markdown('http', 'headers', uri, timeout=90)
        self.assertIn('Name: CF-RAY', result)
