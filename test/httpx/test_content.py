# SPDX-License-Identifier: MPL-2.0

import unittest
from unittest import mock

import base64
import os

from test.common.classes import TestLoggerBase, TestThreadedServerHttp, TestThreadedServerHttps

import urllib3

from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.grade import Grade
from cryptodatahub.common.types import Base64Data
from cryptodatahub.common.utils import HttpFetcher, hash_bytes

from cryptoparser.common.field import FieldValueMimeType, MimeTypeRegistry
from cryptoparser.httpx.version import HttpVersion

from cryptolyzer.httpx.client import L7ClientHttpBase
from cryptolyzer.httpx.content import (
    AnalyzerConetnt,
    HttpTagIntegrityGetter,
    HttpTagScriptIntegrity,
    HttpTagScriptIntegrityUnparsed,
    HttpTagSourceGetter,
    HttpTagSourced,
)


class TestHttpTagIntegrityGetter(unittest.TestCase):
    def test_error_invalid_integrity(self):
        self.assertEqual(
            HttpTagIntegrityGetter()('https://example.com', b''.join([
                b'<!DOCTYPE html>',
                b'<html>',
                b'  <head>',
                b'    <script src="/head.min.js" integrity="invalid"></script>',
                b'  </head>',
                b'  <body>',
                b'    <script src="/body.min.js" integrity="invalid"></script>',
                b'  </body>',
                b'</html>',
            ])),
            set([
                HttpTagScriptIntegrityUnparsed(
                    source_url=urllib3.util.Url(path='/head.min.js'), integrity='invalid'
                ),
                HttpTagScriptIntegrityUnparsed(
                    source_url=urllib3.util.Url(path='/body.min.js'), integrity='invalid'
                ),
            ])
        )

    def test_empty(self):
        self.assertEqual(HttpTagIntegrityGetter()('https://example.com', b''), set())

    def test_no_integrity(self):
        self.assertEqual(
            HttpTagIntegrityGetter()('https://example.com', b''.join([
                b'<!DOCTYPE html>',
                b'<html>',
                b'  <head>',
                b'    <script src="/head.min.js"></script>',
                b'  </head>',
                b'  <body>',
                b'    <script src="/body.min.js"></script>',
                b'  </body>',
                b'</html>',
            ])),
            set()
        )

    def test_integrity(self):
        script_data = b'abc'
        script_data_base64 = base64.b64encode(script_data).decode('ascii')

        sha2_256_hash_bytes = hash_bytes(Hash.SHA2_256, script_data)
        sha2_256_hash_base64_content = Base64Data(sha2_256_hash_bytes)
        sha2_384_hash_bytes = hash_bytes(Hash.SHA2_384, script_data)
        sha2_384_hash_base64_content = Base64Data(sha2_384_hash_bytes)
        sha2_512_hash_bytes = hash_bytes(Hash.SHA2_512, script_data)
        sha2_512_hash_base64_content = Base64Data(sha2_512_hash_bytes)

        test_http_server = TestThreadedServerHttp('127.0.0.1', 0)
        test_http_server.init_connection()
        test_http_server.start()
        html_url = f'http://127.0.0.1:{test_http_server.bind_port}'

        self.assertEqual(
            HttpTagIntegrityGetter()(html_url, '\n'.join([
                '<!DOCTYPE html>',
                '<html>',
                '  <head>',
                f'    <script integrity="sha256-{sha2_256_hash_base64_content}" '
                'src="/test/common/data/subresource1.js"></script>',
                f'    <script integrity="sha384-{sha2_384_hash_base64_content}" '
                'src="/test/common/data/subresource2.js"></script>',
                '  </head>',
                '  <body>',
                f'    <script integrity="sha512-{sha2_512_hash_base64_content}" '
                'src="/test/common/data/subresource3.js"></script>',
                '    <div>',
                f'      <script integrity="sha512-{script_data_base64}" '
                'src="/test/common/data/subresource4.js"></script>',
                '    </div>',
                '  </body>',
                '</html>',
            ]).encode('ascii')),
            set([
                HttpTagScriptIntegrity(
                    source_url=urllib3.util.Url(path='/test/common/data/subresource1.js'),
                    hash_algorithm=Hash.SHA2_256,
                    hash_value=sha2_256_hash_base64_content,
                    is_hash_correct=True,
                ),
                HttpTagScriptIntegrity(
                    source_url=urllib3.util.Url(path='/test/common/data/subresource2.js'),
                    hash_algorithm=Hash.SHA2_384,
                    hash_value=sha2_384_hash_base64_content,
                    is_hash_correct=True,
                ),
                HttpTagScriptIntegrity(
                    source_url=urllib3.util.Url(path='/test/common/data/subresource3.js'),
                    hash_algorithm=Hash.SHA2_512,
                    hash_value=sha2_512_hash_base64_content,
                    is_hash_correct=True,
                ),
                HttpTagScriptIntegrity(
                    source_url=urllib3.util.Url(path='/test/common/data/subresource4.js'),
                    hash_algorithm=Hash.SHA2_512,
                    hash_value=script_data_base64,
                    is_hash_correct=False,
                ),
            ])
        )

        test_http_server.kill()


class TestHttpTagSourceGetter(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(HttpTagSourceGetter()(b''), set())

    def test_sources(self):
        self.assertEqual(
            HttpTagSourceGetter()(b''.join([
                b'<!DOCTYPE html>',
                b'<html>',
                b'  <body>',
                b'    <img src="/img"/>',
                b'    <audio src="/audio"/>',
                b'    <iframe src="/iframe"/>',
                b'    <link href="/link"/>',
                b'    <link href="/link"/ rel="stylesheet">',
                b'    <object data="/object"/>',
                b'    <script src="/script"/>',
                b'    <video src="/video"/>',
                b'  </body>',
                b'</html>',
            ])), set([
                HttpTagSourced('img', '/img'),
                HttpTagSourced('audio', '/audio'),
                HttpTagSourced('iframe', '/iframe'),
                HttpTagSourced('link', '/link'),
                HttpTagSourced('object', '/object'),
                HttpTagSourced('script', '/script'),
                HttpTagSourced('video', '/video'),
            ])
        )


class TestHttpContent(TestLoggerBase):
    @classmethod
    def get_result(cls, uri, timeout=None):
        analyzer = AnalyzerConetnt()
        client = L7ClientHttpBase.from_uri(urllib3.util.parse_url(uri))
        if timeout:
            client.timeout = timeout
        return analyzer.analyze(client, HttpVersion.HTTP1_1)

    def test_relative_sources(self):
        relative_links = b''.join([
            b'<!DOCTYPE html>',
            b'<html>',
            b'  <body>',
            b'    <img src="/img"/>',
            b'    <audio src="/audio"/>',
            b'    <iframe src="/iframe"/>',
            b'    <link href="/link"/ rel="stylesheet">',
            b'    <object data="/object"/>',
            b'    <script src="/script"/>',
            b'    <video src="/video"/>',
            b'  </body>',
            b'</html>',
        ])

        mock_response = mock.Mock()
        mock_response.headers = {'Content-Type': 'text/html; charset=utf-8'}
        mock_response.data = relative_links

        def mock_fetch(self, url):  # pylint: disable=unused-argument
            object.__setattr__(self, '_response', mock_response)

        with mock.patch.object(HttpFetcher, 'fetch', mock_fetch):
            analyzer_result = self.get_result('https://example.org')
            self.assertEqual(analyzer_result.unencrypted_sources, [])
        with mock.patch.object(HttpFetcher, 'fetch', mock_fetch):
            analyzer_result = self.get_result('http://example.org')
            self.assertEqual(len(analyzer_result.unencrypted_sources), 7)

        absolute_links = b''.join([
            b'<!DOCTYPE html>',
            b'<html>',
            b'  <body>',
            b'    <img src="http://example.org/img"/>',
            b'    <audio src="http://example.org/audio"/>',
            b'    <iframe src="http://example.org/iframe"/>',
            b'    <link href="http://example.org/link" rel="stylesheet"/>',
            b'    <object data="http://example.org/object"/>',
            b'    <script src="http://example.org/script"/>',
            b'    <video src="http://example.org/video"/>',
            b'  </body>',
            b'</html>',
        ])
        mock_response_absolute = mock.Mock()
        mock_response_absolute.headers = {'Content-Type': 'text/html; charset=utf-8'}
        mock_response_absolute.data = absolute_links

        def mock_fetch_absolute(self, url):  # pylint: disable=unused-argument
            object.__setattr__(self, '_response', mock_response_absolute)

        with mock.patch.object(HttpFetcher, 'fetch', mock_fetch_absolute):
            analyzer_result = self.get_result('http://example.org')
            self.assertEqual(len(analyzer_result.unencrypted_sources), 7)

    def test_real(self):
        mime_type_html = FieldValueMimeType('html', MimeTypeRegistry.TEXT)

        os.environ['SSL_CERT_FILE'] = str(TestThreadedServerHttps.CA_CERT_FILE_PATH)
        self.addCleanup(os.environ.pop, 'SSL_CERT_FILE', None)

        test_https_server = TestThreadedServerHttps('127.0.0.1', 0)
        test_https_server.init_connection()
        test_https_server.start()
        base_url = f'https://127.0.0.1:{test_https_server.bind_port}/test/common/data'

        analyzer_result = self.get_result(f'{base_url}/content-no-integrity.html')
        self.assertEqual(analyzer_result.mime_type, mime_type_html)
        self.assertEqual(len(analyzer_result.script_integrity), 0)

        analyzer_result = self.get_result(f'{base_url}/content-integrity.html')
        self.assertEqual(analyzer_result.mime_type, mime_type_html)
        self.assertEqual(len(analyzer_result.script_integrity), 4)
        self.assertTrue(all(map(
            lambda script_integrity: script_integrity.is_hash_correct,
            analyzer_result.script_integrity
        )))
        self.assertEqual(len(analyzer_result.unencrypted_sources), 0)

        analyzer_result = self.get_result(f'{base_url}/content-mixed-single.html')
        self.assertEqual(analyzer_result.mime_type, mime_type_html)
        self.assertEqual(analyzer_result.script_integrity, [])
        self.assertEqual(len(analyzer_result.unencrypted_sources), 1)

        unencrypted_source = analyzer_result.unencrypted_sources[0]
        self.assertEqual(unencrypted_source.data_type.value, 'script')
        self.assertEqual(unencrypted_source.data_type.grade, Grade.INSECURE)
        self.assertEqual(str(unencrypted_source.source_url), 'http://mixed-script.badssl.com/nonsecure.js')

        analyzer_result = self.get_result(f'{base_url}/content-mixed-multiple.html')
        self.assertEqual(analyzer_result.mime_type, mime_type_html)
        self.assertEqual(analyzer_result.script_integrity, [])
        self.assertEqual(len(analyzer_result.unencrypted_sources), 2)

        unencrypted_source = analyzer_result.unencrypted_sources[0]
        self.assertEqual(unencrypted_source.data_type.value, 'img')
        self.assertEqual(unencrypted_source.data_type.grade, Grade.WEAK)
        self.assertEqual(str(unencrypted_source.source_url), 'http://very.badssl.com/image.jpg')
        unencrypted_source = analyzer_result.unencrypted_sources[1]
        self.assertEqual(unencrypted_source.data_type.value, 'script')
        self.assertEqual(unencrypted_source.data_type.grade, Grade.INSECURE)
        self.assertEqual(str(unencrypted_source.source_url), 'http://http.badssl.com/test/imported.js')

        test_https_server.kill()
