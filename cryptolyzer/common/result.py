# -*- coding: utf-8 -*-

import ipaddress
import six
import attr

from cryptoparser.common.base import Serializable
from cryptoparser.httpx.version import HttpVersion
from cryptoparser.ssh.version import SshProtocolVersion
from cryptoparser.tls.version import TlsProtocolVersion


@attr.s
class AnalyzerTargetBase(Serializable):
    scheme = attr.ib(validator=attr.validators.instance_of(six.string_types))
    address = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @classmethod
    def _from_l7_client(cls, l7_client, **kwargs):
        raise NotImplementedError()

    @classmethod
    def from_l7_client(cls, l7_client, proto_version=None):
        raise NotImplementedError()


@attr.s
class AnalyzerTarget(AnalyzerTargetBase):
    ip = attr.ib(
        validator=attr.validators.instance_of((
            six.string_types, ipaddress.IPv4Address, ipaddress.IPv6Address
        )),
        metadata={'human_readable_name': 'IP address'}
    )
    port = attr.ib(validator=attr.validators.instance_of(int))

    @classmethod
    def _from_l7_client(cls, l7_client, **kwargs):
        return cls(l7_client.get_scheme(), l7_client.address, l7_client.ip, l7_client.port, **kwargs)

    @classmethod
    def from_l7_client(cls, l7_client, proto_version=None):
        return cls._from_l7_client(l7_client, proto_version=proto_version)


@attr.s
class AnalyzerTargetHttp(AnalyzerTarget):
    path = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types)),
    )
    proto_version = attr.ib(
        default=HttpVersion.HTTP1_1,
        validator=attr.validators.optional(attr.validators.in_(HttpVersion)),
        metadata={'human_readable_name': 'Protocol Version'}
    )

    @classmethod
    def _from_l7_client(cls, l7_client, **kwargs):
        if l7_client.uri.port is None:
            port = l7_client.get_default_port()
        else:
            port = int(l7_client.uri.port)

        return cls(l7_client.get_scheme(), l7_client.uri.host, '', port, path=l7_client.uri.path)


@attr.s
class AnalyzerTargetTls(AnalyzerTarget):
    proto_version = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(TlsProtocolVersion)),
        metadata={'human_readable_name': 'Protocol Version'}
    )


@attr.s
class AnalyzerTargetSsh(AnalyzerTarget):
    proto_version = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(SshProtocolVersion)),
        metadata={'human_readable_name': 'Protocol Version'}
    )


@attr.s
class AnalyzerTargetDnsRecord(AnalyzerTargetBase):
    server = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))

    @classmethod
    def _from_l7_client(cls, l7_client, **kwargs):
        return cls(l7_client.get_scheme(), l7_client.domain.host, l7_client.domain.fragment)

    @classmethod
    def from_l7_client(cls, l7_client, proto_version=None):
        return cls._from_l7_client(l7_client)


@attr.s
class AnalyzerResultBase(Serializable):
    target = attr.ib()

    def _as_markdown_without_target(self, value, level):
        multiline, attr_result = self._markdown_result(value, level)
        if not multiline:
            attr_result += '\n'

        if value is not None and isinstance(value, AnalyzerResultBase):
            target_result_line_count = len(self._markdown_result(value.target, level)[1].split('\n'))
            attr_result = '\n'.join(attr_result.split('\n')[target_result_line_count:])

        return attr_result


@attr.s
class AnalyzerResultError(AnalyzerResultBase):
    error = attr.ib(validator=attr.validators.instance_of(six.string_types))


@attr.s
class AnalyzerResultAllBase(AnalyzerResultBase):
    def _as_markdown(self, level):
        result = ''

        dict_value = self._asdict()
        name_dict = self._markdown_human_readable_names(self, dict_value)
        for attr_name, value in dict_value.items():
            result += '{} {}\n\n'.format((level + 1) * '#', name_dict[attr_name])
            if (value is None or isinstance(value, (AnalyzerResultBase, AnalyzerTarget))):
                result += self._as_markdown_without_target(value, level)
            else:
                for index, cipher_result in enumerate(value):
                    if index:
                        result += '\n'

                    result += '{} {}\n\n'.format((level + 2) * '#', cipher_result.target.proto_version)
                    result += self._as_markdown_without_target(cipher_result, level)
            result += '\n'

        return True, result


@attr.s
class AnalyzerResultTls(AnalyzerResultBase):
    pass


@attr.s
class AnalyzerResultSsh(AnalyzerResultBase):
    pass


@attr.s
class AnalyzerResultHttp(AnalyzerResultBase):
    pass


@attr.s
class AnalyzerResultDnsRecord(AnalyzerResultBase):
    pass
