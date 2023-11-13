# -*- coding: utf-8 -*-

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    from unittest import mock
except ImportError:
    import mock

import base64

from test.common.classes import TestLoggerBase

import urllib3

from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.types import Base64Data
from cryptodatahub.common.utils import HttpFetcher, hash_bytes

from cryptoparser.httpx.version import HttpVersion
from cryptoparser.httpx.header import HttpHeaderFieldValueContentTypeMimeType, MimeTypeRegistry

from cryptolyzer.httpx.client import L7ClientHttpBase
from cryptolyzer.httpx.content import (
    AnalyzerConetnt,
    HttpTagIntegrityGetter,
    HttpTagScriptIntegrity,
    HttpTagScriptIntegrityUnparsed,
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
                '    <script integrity="sha256-%s" src="/head.1.js"></script>' % (sha2_256_hash_base64_content),
                '    <script integrity="sha384-%s" src="/head.2.js"></script>' % (sha2_384_hash_base64_content),
                '  </head>',
                '  <body>',
                '    <script integrity="sha512-%s" src="/body.root.js"></script>' % (sha2_512_hash_base64_content),
                '    <div>',
                '      <script integrity="sha512-%s" src="/body.inner.js"></script>' % (script_data_base64),
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


class TestHttpContent(TestLoggerBase):
    @classmethod
    def get_result(cls, uri, timeout=None):
        analyzer = AnalyzerConetnt()
        client = L7ClientHttpBase.from_uri(urllib3.util.parse_url(uri))
        if timeout:
            client.timeout = timeout
        return analyzer.analyze(client, HttpVersion.HTTP1_1)

    def test_real(self):
        analyzer_result = self.get_result('https://www.cloudflare.com')
        self.assertEqual(
            analyzer_result.mime_type,
            HttpHeaderFieldValueContentTypeMimeType('html', MimeTypeRegistry.TEXT)
        )
        self.assertEqual(len(analyzer_result.script_integrity), 1)
        self.assertTrue(analyzer_result.script_integrity[0].is_hash_correct)
