# -*- coding: utf-8 -*-

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import unittest

import socket
import sys
import threading
import time

import six

from cryptolyzer.__main__ import main


class TestMainBase(unittest.TestCase):
    @staticmethod
    def _get_arguments(protocol_version, analyzer, hostname, port):
        ip_address = socket.gethostbyname(hostname)

        func_arguments = {
            'protocol_version': None if isinstance(protocol_version, str) else protocol_version,
            'host': hostname,
            'ip': ip_address,
            'port': port
        }
        cli_arguments = {
            'protocol': protocol_version if isinstance(protocol_version, str) else protocol_version.identifier,
            'analyzer': analyzer,
            'address': '{hostname}:{port}#{ip_address}'.format(
                hostname=hostname,
                port=port,
                ip_address=ip_address
            )
        }

        return func_arguments, cli_arguments

    @staticmethod
    def _get_test_analyzer_result(output_format, protocol, analyzer, address):
        with patch('sys.stdout', new_callable=six.StringIO) as stdout, \
                patch.object(
                    sys, 'argv', ['cryptolyzer', '--output-format', output_format, protocol, analyzer, address]
                ):
            main()
            return stdout.getvalue()

    @staticmethod
    def _get_test_analyzer_result_json(protocol, analyzer, address):
        return TestMainBase._get_test_analyzer_result('json', protocol, analyzer, address)

    @staticmethod
    def _get_test_analyzer_result_markdown(protocol, analyzer, address):
        return TestMainBase._get_test_analyzer_result('markdown', protocol, analyzer, address)


class TestThreadedServer(threading.Thread):
    def __init__(self, server):
        super(TestThreadedServer, self).__init__()

        self._server = server
        self._server.init_connection()

    def wait_for_server_listen(self, expiry_in_sec=1):
        self.start()

        for _ in range(10 * expiry_in_sec):
            time.sleep(0.1)
            try:
                self._server.port
            except NotImplementedError:
                pass
            else:
                break
        else:
            raise TimeoutError()
