#!/usr/bin/env python
# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import argparse
import concurrent.futures
import colorama
import urllib3

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.base import Serializable
from cryptoparser.common.exception import InvalidDataLength, InvalidType

from cryptolyzer.common.analyzer import ProtocolHandlerBase
from cryptolyzer.common.exception import NetworkError, SecurityError
from cryptolyzer.common.result import AnalyzerResultError
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.common.utils import SerializableTextEncoderHighlighted

from cryptolyzer import __setup__


def get_protocol_handler_analyzer_and_uris(parser, arguments):
    def to_uri(value, default):
        if '://' not in value:
            value = default + '://' + value

        return urllib3.util.parse_url(value)

    protocol_handler = ProtocolHandlerBase.from_protocol(arguments.protocol)
    analyzer = protocol_handler.analyzer_from_name(arguments.analyzer)
    protocol = analyzer.get_default_scheme()
    clients = analyzer.get_clients()

    supported_schemes = set().union(*[client.get_supported_schemes() for client in clients])
    targets = [to_uri(argument_uri, protocol) for argument_uri in arguments.targets]

    unsupported_schemes = [
        analyzable_uri.scheme
        for analyzable_uri in targets
        if analyzable_uri.scheme not in supported_schemes
    ]
    if unsupported_schemes:
        parser.error(f'unsupported protocol: {", ".join(unsupported_schemes)}')

    return protocol_handler, analyzer, targets


def parse_arg_parallel(value):
    value = int(value)

    if value < 1:
        raise argparse.ArgumentTypeError(f'{value} parallel must be a positive integer value')

    return value


def parse_arg_socket_timeout(value):
    value = float(value)

    if value <= 0:
        raise argparse.ArgumentTypeError(f'{value} socket timeout must be a positive integer value')

    return value


def parse_arg_http_proxy(value):
    proxy_url = urllib3.util.parse_url(value)

    if proxy_url.scheme is None:
        proxy_url = urllib3.util.parse_url('http://' + str(proxy_url))

    if proxy_url.scheme != 'http':
        raise argparse.ArgumentTypeError('only HTTP proxy is supported')

    return proxy_url


def get_argument_parser():
    parser = argparse.ArgumentParser(prog='cryptolyze')
    parser.add_argument('--version', '-v', action='version', version='%(prog)s ' + __setup__.__version__)
    parser.add_argument(
        '--log-level',
        choices=['debug', 'info', 'warning', 'error', 'critical'],
        default='info',
        help='level of logging (default: %(default)s)'
    )
    parser.add_argument(
        '--output-format',
        choices=['json', 'markdown', 'highlighted'],
        default='highlighted',
        help='format of the anlysis result (default: %(default)s)'
    )
    parser.add_argument(
        '-j', '--parallel',
        type=parse_arg_parallel,
        default=1,
        metavar='count',
        help='Number of targets to analyze in parallel (default: %(default)s)'
    )
    parser.add_argument(
        '-t', '--socket-timeout',
        type=parse_arg_socket_timeout,
        default=5.0,
        metavar='seconds',
        help='Maximum time to wait for server to responde (default: %(default)s seconds)'
    )
    parser.add_argument(
        '-p', '--http-proxy',
        type=parse_arg_http_proxy,
        help='Tunnel the traffic through a HTTP CONNECT proxy given in the format "http://USER:PW@HOST:PORT/"'
        '(considered only if in the case of TCP connections)',
        dest="http_proxy",
        default=None,
    )

    parsers_analyzer = parser.add_subparsers(title='protocol', dest='protocol')
    parsers_analyzer.required = True
    for protocol in ProtocolHandlerBase.get_protocols():
        protocol_handler = ProtocolHandlerBase.from_protocol(protocol)
        analyzers = protocol_handler.get_analyzers()
        parser_analyzer = parsers_analyzer.add_parser(protocol)

        parsers_plugin = parser_analyzer.add_subparsers(title='analyzer', dest='analyzer')
        parsers_plugin.required = True
        for analyzer_class in analyzers:
            parser_plugin = parsers_plugin.add_parser(analyzer_class.get_name(), help=analyzer_class.get_help())
            schemes = [client.get_scheme() for client in analyzer_class.get_clients()]
            scheme_list = ','.join(schemes)
            parser_plugin.add_argument(
                'targets', metavar='URI', nargs='+', help=f'[{{{scheme_list}}}://]f.q.d.n[:port][#ip]'
            )

    return parser


def _analyze_target(protocol_handler, analyzer, target, l4_socket_params):
    try:
        return protocol_handler.analyze(analyzer, target, l4_socket_params)
    except (NetworkError, SecurityError, InvalidDataLength, InvalidType, InvalidValue) as e:
        return AnalyzerResultError(str(target), str(e))


def _print_result(analyzer_result, output_format):
    if output_format == 'highlighted':
        print(analyzer_result.as_markdown())
    elif output_format == 'json':
        print(analyzer_result.as_json())
    elif output_format == 'markdown':
        print(analyzer_result.as_markdown())
    else:
        raise NotImplementedError()


def main():
    parser = get_argument_parser()
    arguments = parser.parse_args()
    protocol_handler, analyzer, targets = get_protocol_handler_analyzer_and_uris(parser, arguments)

    if arguments.output_format == 'highlighted':
        colorama.init(strip=False)
        Serializable.post_text_encoder = SerializableTextEncoderHighlighted()

    l4_socket_params = L4TransferSocketParams(
        timeout=arguments.socket_timeout,
        http_proxy=arguments.http_proxy if arguments.http_proxy else None,
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.parallel) as executor:
        for analyzer_result in executor.map(
            _analyze_target,
            [protocol_handler] * len(targets),
            [analyzer] * len(targets),
            targets,
            [l4_socket_params] * len(targets),
        ):
            _print_result(analyzer_result, arguments.output_format)


if __name__ == '__main__':
    main()  # pragma: no cover
