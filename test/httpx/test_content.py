# -*- coding: utf-8 -*-

import unittest
from unittest import mock

import base64

from test.common.classes import TestLoggerBase

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

    @mock.patch.object(HttpFetcher, 'response_data', mock.PropertyMock(return_value=b'javascript content'))
    def test_integrity(self):
        script_data = b'javascript content'
        script_data_base64 = base64.b64encode(script_data).decode('ascii')

        sha2_256_hash_bytes = hash_bytes(Hash.SHA2_256, script_data)
        sha2_256_hash_base64_content = Base64Data(sha2_256_hash_bytes)
        sha2_384_hash_bytes = hash_bytes(Hash.SHA2_384, script_data)
        sha2_384_hash_base64_content = Base64Data(sha2_384_hash_bytes)
        sha2_512_hash_bytes = hash_bytes(Hash.SHA2_512, script_data)
        sha2_512_hash_base64_content = Base64Data(sha2_512_hash_bytes)

        self.assertEqual(
            HttpTagIntegrityGetter()('https://example.com', '\n'.join([
                '<!DOCTYPE html>',
                '<html>',
                '  <head>',
                f'    <script integrity="sha256-{sha2_256_hash_base64_content}" src="/head.1.js"></script>',
                f'    <script integrity="sha384-{sha2_384_hash_base64_content}" src="/head.2.js"></script>',
                '  </head>',
                '  <body>',
                f'    <script integrity="sha512-{sha2_512_hash_base64_content}" src="/body.root.js"></script>',
                '    <div>',
                f'      <script integrity="sha512-{script_data_base64}" src="/body.inner.js"></script>',
                '    </div>',
                '  </body>',
                '</html>',
            ]).encode('ascii')),
            set([
                HttpTagScriptIntegrity(
                    source_url=urllib3.util.Url(path='/head.1.js'),
                    hash_algorithm=Hash.SHA2_256,
                    hash_value=sha2_256_hash_base64_content,
                    is_hash_correct=True,
                ),
                HttpTagScriptIntegrity(
                    source_url=urllib3.util.Url(path='/head.2.js'),
                    hash_algorithm=Hash.SHA2_384,
                    hash_value=sha2_384_hash_base64_content,
                    is_hash_correct=True,
                ),
                HttpTagScriptIntegrity(
                    source_url=urllib3.util.Url(path='/body.root.js'),
                    hash_algorithm=Hash.SHA2_512,
                    hash_value=sha2_512_hash_base64_content,
                    is_hash_correct=True,
                ),
                HttpTagScriptIntegrity(
                    source_url=urllib3.util.Url(path='/body.inner.js'),
                    hash_algorithm=Hash.SHA2_512,
                    hash_value=script_data_base64,
                    is_hash_correct=False,
                ),
            ])
        )


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

        with mock.patch.object(HttpFetcher, 'response_data', mock.PropertyMock(return_value=relative_links)):
            analyzer_result = self.get_result('https://example.org')
            self.assertEqual(analyzer_result.unencrypted_sources, [])
        with mock.patch.object(HttpFetcher, 'response_data', mock.PropertyMock(return_value=relative_links)):
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
        with mock.patch.object(HttpFetcher, 'response_data', mock.PropertyMock(return_value=absolute_links)):
            analyzer_result = self.get_result('http://example.org')
            self.assertEqual(len(analyzer_result.unencrypted_sources), 7)

    def test_real(self):
        mime_type_html = FieldValueMimeType('html', MimeTypeRegistry.TEXT)

        analyzer_result = self.get_result('https://www.cloudflare.com')
        self.assertEqual(analyzer_result.mime_type, mime_type_html)
        self.assertEqual(len(analyzer_result.script_integrity), 0)

        analyzer_result = self.get_result('https://letsencrypt.org')
        self.assertEqual(analyzer_result.mime_type, mime_type_html)
        self.assertEqual(len(analyzer_result.script_integrity), 4)
        self.assertTrue(all(map(
            lambda script_integrity: script_integrity.is_hash_correct,
            analyzer_result.script_integrity
        )))
        self.assertEqual(len(analyzer_result.unencrypted_sources), 0)

        analyzer_result = self.get_result('https://mixed-script.badssl.com')
        self.assertEqual(analyzer_result.mime_type, mime_type_html)
        self.assertEqual(analyzer_result.script_integrity, [])
        self.assertEqual(len(analyzer_result.unencrypted_sources), 1)

        unencrypted_source = analyzer_result.unencrypted_sources[0]
        self.assertEqual(unencrypted_source.data_type.value, 'script')
        self.assertEqual(unencrypted_source.data_type.grade, Grade.INSECURE)
        self.assertEqual(str(unencrypted_source.source_url), 'http://mixed-script.badssl.com/nonsecure.js')

        analyzer_result = self.get_result('https://very.badssl.com')
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
