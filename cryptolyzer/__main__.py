#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import urllib3

from cryptoparser.common.utils import get_leaf_classes

from cryptolyzer.common.analyzer import ProtocolHandlerBase


def get_handler_and_uris(parser, arguments):
    def to_uri(value, default):
        if u'://' not in value:
            value = default + u'://' + value

        return urllib3.util.parse_url(value)

    protocol_handler = ProtocolHandlerBase.from_protocol(arguments.protocol)
    protocol = protocol_handler.get_protocol()
    clients = protocol_handler.get_clients()

    supported_schemes = set().union(*[client.get_supported_schemes() for client in clients])
    uris = [to_uri(argument_uri, protocol) for argument_uri in arguments.uris]

    if any([analyzable_uri.scheme not in supported_schemes for analyzable_uri in uris]):
        parser.error('{} protocol is not supported'.format(str(analyzable_uri.scheme)))

    return protocol_handler, uris


def get_argument_parser():
    parser = argparse.ArgumentParser(prog='cryptolyze')

    parsers_analyzer = parser.add_subparsers(dest='protocol')
    for protocol_handler_class in get_leaf_classes(ProtocolHandlerBase):
        protocol = protocol_handler_class.get_protocol()
        analyzers = protocol_handler_class.get_analyzers()
        parser_analyzer = parsers_analyzer.add_parser(protocol)

        parsers_plugin = parser_analyzer.add_subparsers(dest='analyzer')
        for analyzer_class in analyzers:
            parser_plugin = parsers_plugin.add_parser(analyzer_class.get_name(), help=analyzer_class.get_help())
            parser_plugin.add_argument('uris', metavar='URI', nargs='+')

    return parser


def main():
    argument_parser = get_argument_parser()
    arguments = argument_parser.parse_args()
    protocol_handler, argument_uris = get_handler_and_uris(argument_parser, arguments)
    analyzer = protocol_handler.analyzer_from_name(arguments.analyzer)

    for analyzer_result in  protocol_handler.analyze([analyzer, ], argument_uris):
        print(analyzer_result.as_json())


if __name__ == '__main__':
    main()
