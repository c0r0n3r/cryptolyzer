#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import urllib3

from cryptolyzer.common.analyzer import ProtocolHandlerBase


def get_handler_and_uris(parser, arguments):
    def to_uri(value, default):
        if u'://' not in value:
            value = default + u'://' + value

        return urllib3.util.parse_url(value)

    protocol_handler = ProtocolHandlerBase.from_protocol(arguments.protocol)
    protocol = protocol_handler.get_default_scheme()
    clients = protocol_handler.get_clients()

    supported_schemes = set().union(*[client.get_supported_schemes() for client in clients])
    uris = [to_uri(argument_uri, protocol) for argument_uri in arguments.uris]

    unsupported_schemes = [
        analyzable_uri.scheme
        for analyzable_uri in uris
        if analyzable_uri.scheme not in supported_schemes
    ]
    if unsupported_schemes:
        parser.error('unsupported protocol: {}'.format(', '.join(unsupported_schemes)))

    return protocol_handler, uris


def get_argument_parser():
    parser = argparse.ArgumentParser(prog='cryptolyze')

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
            schemes = [client.get_scheme() for client in protocol_handler.get_clients()]
            parser_plugin.add_argument(
                'uris', metavar='URI', nargs='+',
                help='[{{{}}}://]f.q.d.n[:port][#ip]'.format(','.join(schemes))
            )

    return parser


def main():
    argument_parser = get_argument_parser()
    arguments = argument_parser.parse_args()
    protocol_handler, argument_uris = get_handler_and_uris(argument_parser, arguments)

    for uri in argument_uris:
        analyzer_result = protocol_handler.analyze(arguments.analyzer, uri)
        print(analyzer_result.as_json())


if __name__ == '__main__':
    main()  # pragma: no cover
