# -*- coding: utf-8 -*-

import six

import attr
import bs4
import urllib3

from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.grade import Grade, GradeableSimple
from cryptodatahub.common.types import convert_base64_data, convert_value_to_object, convert_url, Base64Data
from cryptodatahub.common.utils import hash_bytes, HttpFetcher

from cryptoparser.common.base import Serializable
from cryptoparser.common.field import FieldValueMimeType, MimeTypeRegistry
from cryptoparser.httpx.header import HttpHeaderFieldValueContentType

from cryptolyzer.common.analyzer import AnalyzerHttpBase
from cryptolyzer.common.result import AnalyzerResultHttp, AnalyzerTargetHttp
from cryptolyzer.common.utils import LogSingleton


@attr.s(frozen=True)
class HttpTagSourceDataType(Serializable, GradeableSimple):
    value = attr.ib(validator=attr.validators.instance_of(six.string_types))

    def __str__(self):
        return self.value

    @property
    def active(self):
        return self.value in ('iframe', 'script', 'stylesheet')

    @property
    def grade(self):
        return Grade.INSECURE if self.active else Grade.WEAK


@attr.s(frozen=True)
class HttpTagSourced(object):
    data_type = attr.ib(
        converter=convert_value_to_object(HttpTagSourceDataType),
        validator=attr.validators.instance_of(HttpTagSourceDataType)
    )
    source_url = attr.ib(
        converter=convert_url(),
        validator=attr.validators.instance_of(urllib3.util.url.Url),
        metadata={'human_readable_name': 'Source URL'}
    )


@attr.s(frozen=True)
class HttpTagScriptBase(object):
    source_url = attr.ib(
        validator=attr.validators.instance_of(urllib3.util.url.Url),
        metadata={'human_readable_name': 'Source URL'}
    )


@attr.s(frozen=True)
class HttpTagScriptIntegrityUnparsed(HttpTagScriptBase):
    integrity = attr.ib(validator=attr.validators.instance_of(six.string_types))


@attr.s(frozen=True)
class HttpTagScriptIntegrity(HttpTagScriptBase):
    hash_algorithm = attr.ib(validator=attr.validators.instance_of((Hash, six.string_types)))
    hash_value = attr.ib(converter=convert_base64_data(), validator=attr.validators.instance_of(Base64Data))
    is_hash_correct = attr.ib(validator=attr.validators.instance_of(bool))

    @classmethod
    def from_integrity_params(cls, html_url, source_url, hash_algorithm, hash_value):
        html_url = convert_url()(html_url)

        source_url_params = source_url._asdict()
        if source_url.host is None:
            source_url_params['host'] = html_url.host
        if source_url.host is None:
            source_url_params['scheme'] = html_url.scheme

        http_fetcher = HttpFetcher()
        http_fetcher.fetch(urllib3.util.Url(**source_url_params))

        calculated_hash_value = Base64Data(hash_bytes(hash_algorithm, http_fetcher.response_data))

        return cls(source_url, hash_algorithm, hash_value, convert_base64_data()(hash_value) == calculated_hash_value)


@attr.s
class AnalyzerResultConetnt(AnalyzerResultHttp):  # pylint: disable=too-few-public-methods
    mime_type = attr.ib(validator=attr.validators.instance_of(FieldValueMimeType))
    script_integrity = attr.ib(
        validator=attr.validators.optional(
            attr.validators.deep_iterable(member_validator=attr.validators.instance_of(HttpTagScriptBase))
        )
    )
    unencrypted_sources = attr.ib(
        validator=attr.validators.optional(
            attr.validators.deep_iterable(member_validator=attr.validators.instance_of(HttpTagSourced))
        )
    )


class HttpTagGetterBase(object):
    _SOURCE_ATTR_NAME_BY_TAG_NAME = {
        'img': 'src',
        'audio': 'src',
        'iframe': 'src',
        'link': 'href',
        'object': 'data',
        'script': 'src',
        'video': 'src',
    }

    def _get_source_as_url(self, tag):
        return urllib3.util.url.parse_url(tag.get(self._SOURCE_ATTR_NAME_BY_TAG_NAME[tag.name]))


class HttpTagSourceGetter(HttpTagGetterBase):
    def _is_tag_with_source(self, tag):
        if tag.name not in self._SOURCE_ATTR_NAME_BY_TAG_NAME:
            return False

        attr_name = self._SOURCE_ATTR_NAME_BY_TAG_NAME[tag.name]
        if not tag.has_attr(attr_name):
            return False

        attr_value = tag.get(attr_name)
        return attr_value is not None

    def __call__(self, html_data):
        soup = bs4.BeautifulSoup(html_data, 'html.parser')
        if soup.html is None:
            return set()

        return {
            HttpTagSourced(
                source_url=self._get_source_as_url(tag),
                data_type=tag.get('rel') if tag.name == 'stylesheet' else tag.name
            )
            for tag in soup.html.find_all(self._is_tag_with_source)
            if tag.name != 'link' or tag.get('rel') == ['stylesheet']
        }


class HttpTagIntegrityGetter(HttpTagGetterBase):
    _HASH_ALGORITHM_BY_NAME = {
        'sha256': Hash.SHA2_256,
        'sha384': Hash.SHA2_384,
        'sha512': Hash.SHA2_512,
    }

    @staticmethod
    def _is_tag_script_with_integrity(tag):
        if tag.name != 'script':
            return False

        if not tag.has_attr('integrity'):
            return False

        return True

    def __call__(self, html_url, html_data):
        scripts = set()
        soup = bs4.BeautifulSoup(html_data, 'html.parser')
        if soup.html is None:
            return scripts

        for script in soup.html.find_all(self._is_tag_script_with_integrity):
            integrity = script.get('integrity')
            try:
                hash_algorithm, hash_value = integrity.split('-')
                hash_algorithm = self._HASH_ALGORITHM_BY_NAME[hash_algorithm]
            except ValueError:
                script = HttpTagScriptIntegrityUnparsed(
                    source_url=self._get_source_as_url(script),
                    integrity=integrity,
                )
            else:
                script = HttpTagScriptIntegrity.from_integrity_params(
                    html_url=html_url,
                    source_url=self._get_source_as_url(script),
                    hash_algorithm=hash_algorithm,
                    hash_value=hash_value,
                )
            scripts.add(script)

        return scripts


class AnalyzerConetnt(AnalyzerHttpBase):
    @classmethod
    def get_name(cls):
        return 'content'

    @classmethod
    def get_help(cls):
        return 'Check content responded by the server(s)'

    @staticmethod
    def _analyze_content(analyzable, version):  # pylint: disable=unused-argument
        http_fetcher = HttpFetcher()
        http_fetcher.fetch(analyzable.uri)

        content_type = http_fetcher.get_response_header('Content-Type')
        content_type = HttpHeaderFieldValueContentType.parse_exact_size(content_type.encode('ascii'))
        content_type = HttpHeaderFieldValueContentType(**content_type._asdict())  # workaround PyLint no-member warnings
        charset = (
            content_type.charset.value
            if content_type is not None and content_type.charset is not None
            else 'utf-8'
        )
        LogSingleton().log(level=60, msg=six.u('Server offers content with type %s') % (str(content_type.mime_type)))

        tags_with_integrity = None
        tags_with_unencrypted_source = None
        if content_type.mime_type == FieldValueMimeType('html', MimeTypeRegistry.TEXT):
            html_data = http_fetcher.response_data.decode(charset)

            tags_with_integrity = HttpTagIntegrityGetter()(analyzable.uri, html_data)

            tags_with_source = HttpTagSourceGetter()(html_data)
            tags_with_unencrypted_source = set(filter(
                lambda tag: (
                    tag.source_url.scheme == 'http' or
                    (tag.source_url.scheme is None and tag.source_url.host is None and analyzable.uri.scheme == 'http')
                ),
                tags_with_source
            ))

        return content_type.mime_type, tags_with_integrity, tags_with_unencrypted_source

    def analyze(self, analyzable, protocol_version):
        mime_type, tags_with_integrity, tags_with_unencrypted_source = self._analyze_content(
            analyzable, protocol_version
        )

        return AnalyzerResultConetnt(
            AnalyzerTargetHttp.from_l7_client(analyzable, protocol_version),
            mime_type,
            sorted(tags_with_integrity),
            sorted(tags_with_unencrypted_source),
        )
