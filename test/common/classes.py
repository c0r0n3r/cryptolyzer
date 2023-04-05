# -*- coding: utf-8 -*-

import os

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import io
import logging
import socket
import sys
import threading
import time

import six

from cryptolyzer.common.utils import LogSingleton


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

    def _get_command_result(self, command_line_arguments, stdin=b''):
        with patch('sys.stdout', new_callable=six.StringIO) as stdout, \
                patch('sys.stderr', new_callable=six.StringIO) as stderr, \
                patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(stdin))), \
                patch.object(sys, 'argv', command_line_arguments):
            self.main_func()
            return stdout.getvalue(), stderr.getvalue()

    def _get_test_analyzer_result(self, output_format, protocol, analyzer, address):
        return self._get_command_result([
            'cryptolyzer', '--output-format', output_format, protocol, analyzer, address
        ])

    def _get_test_analyzer_result_json(self, protocol, analyzer, address):
        return self._get_test_analyzer_result('json', protocol, analyzer, address)[0]

    def _get_test_analyzer_result_markdown(self, protocol, analyzer, address):
        return self._get_test_analyzer_result('markdown', protocol, analyzer, address)[0]

    def _test_argument_error(self, argv, stderr_regexp, stdin=b''):
        with patch.object(sys, 'stderr', new_callable=six.StringIO) as stderr, \
                patch.object(sys, 'argv', argv), patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(stdin))):

            with self.assertRaises(SystemExit) as context_manager:
                self.main_func()
            self.assertEqual(context_manager.exception.args[0], 2)
            six.assertRegex(self, stderr.getvalue(), stderr_regexp)

    def _test_argument_help(self, command):
        devnull = six.StringIO()
        with patch.object(sys, 'stdout', devnull), patch.object(sys, 'argv', [str(command), '-h']):
            with self.assertRaises(SystemExit) as context_manager:
                self.main_func()
            self.assertEqual(context_manager.exception.args[0], 0)


class TestThreadedServer(threading.Thread):
    def __init__(self, server):
        super(TestThreadedServer, self).__init__()

        self._server = server
        self._server.init_connection()

    def wait_for_server_listen(self, expiry_in_sec=5):
        self.start()

        if hasattr(self._server, 'bind_port'):
            l4_transfer = self._server
        else:
            l4_transfer = self._server.l4_transfer

        for _ in range(expiry_in_sec * 100):
            time.sleep(1.0 / (expiry_in_sec * 100))
            try:
                if l4_transfer.bind_port != 0:
                    break
            except AttributeError:
                pass
        else:
            if six.PY3:
                raise TimeoutError()

            raise socket.timeout()


class TestLoggerBase(unittest.TestCase):
    def setUp(self):
        log = LogSingleton()
        log.setLevel(logging.INFO)
        self.old_handlers = log.handlers
        for handler in log.handlers:
            log.removeHandler(handler)

        self.log_stream = io.StringIO()
        handler = logging.StreamHandler(self.log_stream)
        log.addHandler(handler)

    def tearDown(self):
        log = LogSingleton()
        for handler in self.old_handlers:
            log.addHandler(handler)

    def _get_log_lines(self, flush):
        log_lines = self.log_stream.getvalue().strip().split(os.linesep)

        if flush:
            self.log_stream.seek(0)
            self.log_stream.truncate(0)

        return log_lines

    def get_log_lines(self):
        return self._get_log_lines(flush=False)

    def pop_log_lines(self):
        return self._get_log_lines(flush=True)
