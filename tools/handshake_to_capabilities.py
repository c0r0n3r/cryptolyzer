# -*- coding: utf-8 -*-

import argparse
import json
import sys

import six

from cryptoparser.common.utils import get_leaf_classes

from cryptolyzer.common.utils import HandshakeToCapabilitiesBase


def main():
    handshake_to_capabilities_classes = {
        handshake_to_capabilities_class.get_protocol(): handshake_to_capabilities_class
        for handshake_to_capabilities_class in get_leaf_classes(HandshakeToCapabilitiesBase)
    }
    parser = argparse.ArgumentParser(prog='handshake_to_capabilities')
    parser.add_argument(
        '--protocol', choices=sorted(handshake_to_capabilities_classes.keys()), help='name of the parsable protocol'
    )
    parser.add_argument(
        '--format', choices=['tshark', ], help='format of the parsable data'
    )
    arguments = parser.parse_args()

    handshake_data = sys.stdin.read()
    if not handshake_data:
        six.print_('No input data', file=sys.stderr)
        sys.exit(2)

    handshake_class = handshake_to_capabilities_classes[arguments.protocol]
    parser_func = getattr(handshake_class, 'from_' + arguments.format)

    try:
        handshake_to_capabilities_object = parser_func(handshake_data)
        client_capabilities = handshake_to_capabilities_object.to_capabilities()
    except (TypeError, ValueError) as e:
        six.print_(e.args[0], file=sys.stderr)
        sys.exit(2)

    print(json.dumps(client_capabilities))


if __name__ == '__main__':
    main()  # pragma: no cover
