# -*- coding: utf-8 -*-

import abc
import http.server
import io
import logging
import os
import pathlib
import socket
import socketserver
import ssl
import sys
import threading
import time
import unittest
from unittest.mock import patch

import attr
import urllib3

import pyfakefs.fake_filesystem_unittest

from cryptodatahub.common.grade import Grade, GradeableComplex, GradeableSimple, GradeableVulnerabilities

from cryptoparser.common.x509 import PublicKeyX509

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.common.utils import LogSingleton


@attr.s(frozen=True, eq=False)
class TestGradeableSimple(GradeableSimple):
    simple_grade = attr.ib(validator=attr.validators.instance_of(Grade))

    @property
    def grade(self):
        return self.simple_grade

    def __str__(self):
        return 'TestGradeableSimple'


@attr.s(frozen=True, eq=False)
class TestGradeableVulnerabilities(GradeableVulnerabilities):
    @classmethod
    def get_gradeable_name(cls):
        return 'TestGradeableName'

    def __str__(self):
        return 'TestGradeable'


@attr.s(frozen=True, eq=False)
class TestGradeableVulnerabilitiesName(GradeableVulnerabilities):
    name = attr.ib(default='name', init=False)

    @classmethod
    def get_gradeable_name(cls):
        return 'TestGradeableName'

    def __str__(self):
        return 'TestGradeableName'


@attr.s(frozen=True, eq=False)
class TestGradeableVulnerabilitiesLongName(GradeableVulnerabilities):
    name = attr.ib(default='name', init=False)
    long_name = attr.ib(default='long name', init=False)

    @classmethod
    def get_gradeable_name(cls):
        return 'TestGradeableLongName'

    def __str__(self):
        return 'TestGradeableLongName'


@attr.s(frozen=True, eq=False)
class TestGradeableComplex(GradeableComplex):
    def __str__(self):
        return 'TestGradeableComplex'

    @classmethod
    def from_gradeables(cls, gradeables):
        gradeable_multiple = cls()
        object.__setattr__(gradeable_multiple, 'gradeables', gradeables)

        return gradeable_multiple


class TestMainBase(unittest.TestCase):
    @classmethod
    def _get_main_func(cls):
        raise NotImplementedError()

    @staticmethod
    def _get_arguments(
            protocol_version, analyzer, hostname, port, timeout=None, scheme=None, proxy=None
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        ip_address = socket.gethostbyname(hostname)

        func_arguments = {
            'protocol_version': None if isinstance(protocol_version, str) else protocol_version,
            'host': hostname,
            'ip': ip_address,
            'port': port,
            'l4_socket_params': L4TransferSocketParams(timeout=timeout, http_proxy=proxy),
        }
        if scheme is not None:
            func_arguments['scheme'] = scheme

        scheme = '' if scheme is None else scheme + '://'
        cli_arguments = {
            'protocol': protocol_version if isinstance(protocol_version, str) else protocol_version.identifier,
            'analyzer': analyzer,
            'address': f'{scheme}{hostname}:{port}#{ip_address}',
            'timeout': timeout,
            'proxy': proxy,
        }

        return func_arguments, cli_arguments

    def _get_command_result(self, command_line_arguments, stdin=b''):
        with patch('sys.stdout', new_callable=io.StringIO) as stdout, \
                patch('sys.stderr', new_callable=io.StringIO) as stderr, \
                patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(stdin))), \
                patch.object(sys, 'argv', command_line_arguments):
            self._get_main_func()()
            return stdout.getvalue(), stderr.getvalue()

    def _get_test_analyzer_result(
            self, output_format, protocol, analyzer, address, timeout=None, proxy=None
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        command_line_arguments = ['cryptolyzer']
        if timeout:
            command_line_arguments.extend(['--socket-timeout', str(timeout)])
        if proxy:
            command_line_arguments.extend(['--http-proxy', str(proxy)])
        command_line_arguments.extend(['--output-format', output_format, protocol, analyzer, address])
        return self._get_command_result(command_line_arguments)

    def _get_test_analyzer_result_json(
        self, protocol, analyzer, address, timeout=None, proxy=None
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        return self._get_test_analyzer_result('json', protocol, analyzer, address, timeout, proxy)[0]

    def _get_test_analyzer_result_markdown(
        self, protocol, analyzer, address, timeout=None, proxy=None
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        return self._get_test_analyzer_result('markdown', protocol, analyzer, address, timeout, proxy)[0]

    def _get_test_analyzer_result_highlighted(
        self, protocol, analyzer, address, timeout=None, proxy=None
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        return self._get_test_analyzer_result('highlighted', protocol, analyzer, address, timeout, proxy)[0]

    def _test_argument_error(self, argv, stderr_regexp, stdin=b''):
        with patch.object(sys, 'stderr', new_callable=io.StringIO) as stderr, \
                patch.object(sys, 'argv', argv), patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(stdin))):

            with self.assertRaises(SystemExit) as context_manager:
                self._get_main_func()()
            self.assertEqual(context_manager.exception.args[0], 2)
            self.assertRegex(stderr.getvalue(), stderr_regexp)

    def _test_argument_help(self, command):
        devnull = io.StringIO()
        with patch.object(sys, 'stdout', devnull), patch.object(sys, 'argv', [str(command), '-h']):
            with self.assertRaises(SystemExit) as context_manager:
                self._get_main_func()()
            self.assertEqual(context_manager.exception.args[0], 0)


class TestHTTPRequestHandlerBase(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        pass

    def version_string(self):
        return self.__class__.__name__

    def date_time_string(self, timestamp=None):  # pylint: disable=no-self-use,unused-argument
        return 'Thu, 01 Jan 1970 00:00:00 GMT'


class TestHTTPProxyRequestHandler(TestHTTPRequestHandlerBase):
    _RESPONSE_TEMPLATE = "{} {} Connection established\r\n\r\n"

    @staticmethod
    def _get_response_code():
        return 200

    def do_CONNECT(self):  # pylint: disable=invalid-name
        server_url = urllib3.util.parse_url(self.path)
        response_code = self._get_response_code()
        _server_socket = socket.create_connection((str(server_url.host), server_url.port))
        response = self._RESPONSE_TEMPLATE.format(self.protocol_version, response_code)
        self.connection.send(response.encode("ascii"))

        while response_code == 200:
            try:
                bytes_received = self.connection.recv(1024)
                _server_socket.send(bytes_received)

                bytes_received = _server_socket.recv(1024)
                self.connection.send(bytes_received)
            except socket.error:
                break

        _server_socket.close()


class TestThreadedServerHttpBase(threading.Thread):
    def __init__(self, address, port):
        super().__init__()

        self.address = address
        self.port = port
        self.server = None

    @abc.abstractmethod
    def init_connection(self):
        raise NotImplementedError()

    @property
    def bind_port(self):
        return self.server.socket.getsockname()[1]

    def run(self):
        self.server.serve_forever()

    def kill(self):
        self.server.socket.close()
        self.server.shutdown()


class TestHTTPRequestHandler(TestHTTPRequestHandlerBase):
    pass


class TestThreadedServerHttpProxy(TestThreadedServerHttpBase):
    def init_connection(self):
        self.server = socketserver.TCPServer((self.address, self.port), TestHTTPProxyRequestHandler)
        self.server.timeout = 5


class TestThreadedServerHttp(TestThreadedServerHttpBase):
    def init_connection(self):
        self.server = socketserver.TCPServer((self.address, self.port), TestHTTPRequestHandler)
        self.server.timeout = 5


class TestThreadedServerHttps(TestThreadedServerHttpBase):
    KEY_FILE_PATH = pathlib.Path(__file__).parent / 'certs' / 'snakeoil_key.pem'
    CERT_FILE_PATH = pathlib.Path(__file__).parent / 'certs' / 'snakeoil_cert.pem'
    CA_CERT_FILE_PATH = pathlib.Path(__file__).parent / 'certs' / 'snakeoil_ca_cert.pem'

    def __init__(self, address, port):
        super().__init__(address, port)

        self.ssl_context = None

    def init_connection(self):
        self.server = socketserver.TCPServer((self.address, self.port), TestHTTPRequestHandler, False)

        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(certfile=str(self.CERT_FILE_PATH), keyfile=str(self.KEY_FILE_PATH))
        self.ssl_context.set_ciphers('ALL')

        self.server.socket = self.ssl_context.wrap_socket(self.server.socket, server_side=True)
        self.server.server_bind()
        self.server.server_activate()


class TestThreadedServer(threading.Thread):
    def __init__(self, server):
        super().__init__()

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
            raise TimeoutError()


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


class TestKeyBase(pyfakefs.fake_filesystem_unittest.TestCase):
    def setUp(self):
        self.setUpPyfakefs()

        self.__certs_dir = pathlib.PurePath(__file__).parent.parent / 'common' / 'certs'
        self.fs.add_real_directory(str(self.__certs_dir))
        self.fs.add_real_directory('/etc/')
        self.fs.add_real_directory('/usr/')

    def _get_pem_str(self, public_key_file_name):
        public_key_path = self.__certs_dir / public_key_file_name
        with open(str(public_key_path), 'r', encoding='ascii') as pem_file:
            return pem_file.read()

    def _get_public_key_x509(self, public_key_file_name):
        return PublicKeyX509.from_pem(self._get_pem_str(public_key_file_name))
