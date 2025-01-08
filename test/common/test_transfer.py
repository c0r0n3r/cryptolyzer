# -*- coding: utf-8 -*-

import socket
import unittest
from unittest import mock

from test.common.classes import (
    TestThreadedServer,
    TestThreadedServerHttp,
    TestThreadedServerHttpProxy,
    TestHTTPProxyRequestHandler,
)

import urllib3

from cryptoparser.common.exception import NotEnoughData

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4ClientTCP, L4ServerTCP, L4ClientUDP, L4ServerUDP, L4TransferSocketParams


class TestL4ClientTCP(unittest.TestCase):
    @staticmethod
    def _create_client_and_receive_text(address, port, receivable_byte_num, to_be_closed=True):
        l4_client = L4ClientTCP(address, port)
        l4_client.init_connection()
        l4_client.receive(receivable_byte_num)
        result = l4_client.buffer.decode('ascii')
        if to_be_closed:
            l4_client.close()

        return l4_client, result

    def test_receive_uninitialized(self):
        l4_client = L4ClientTCP('smtp.gmail.com', 587)
        with self.assertRaises(NotEnoughData) as context_manager:
            l4_client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_error_on_close(self):
        address = 'smtp.gmail.com'
        l4_client, _ = self._create_client_and_receive_text(address, 587, 4 + len(address), to_be_closed=False)
        sock = l4_client._socket  # pylint: disable=protected-access
        with mock.patch.object(socket.socket, 'close', side_effect=socket.error):
            l4_client.close()
        sock.close()

        l4_client, _ = self._create_client_and_receive_text(address, 587, 4 + len(address), to_be_closed=False)
        sock = l4_client._socket  # pylint: disable=protected-access
        with mock.patch.object(socket.socket, 'close', side_effect=NotImplementedError('not a timeout error')):
            with self.assertRaises(NotImplementedError) as context_manager:
                l4_client.close()
            self.assertEqual(context_manager.exception.args, ('not a timeout error', ))
        sock.close()

    def test_error_connection_refused(self):
        with mock.patch.object(socket, 'create_connection', side_effect=ConnectionRefusedError), \
                self.assertRaises(NetworkError) as context_manager:
            l4_client = L4ClientTCP('badssl.com', 443)
            l4_client.init_connection()
        l4_client.close()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_error_unhandled_exception_rethrown(self):
        with mock.patch.object(socket, 'create_connection', side_effect=NotImplementedError), \
                self.assertRaises(NotImplementedError):
            self._create_client_and_receive_text('badssl.com', 443, 1)

    @mock.patch.object(TestHTTPProxyRequestHandler, '_get_response_code', return_value=500)
    def test_error_proxy_result_not_http_ok(self, _):
        test_http_server = TestThreadedServerHttp('127.0.0.1', 0)
        test_http_server.init_connection()
        test_http_server.start()

        test_http_proxy_server = TestThreadedServerHttpProxy('127.0.0.2', 0)
        test_http_proxy_server.init_connection()
        test_http_proxy_server.start()

        http_proxy_url = urllib3.util.parse_url(f'http://127.0.0.2:{test_http_proxy_server.bind_port}')
        l4_client = L4ClientTCP(
            '127.0.0.1', test_http_server.bind_port,
            socket_params=L4TransferSocketParams(http_proxy=http_proxy_url)
        )
        with self.assertRaises(NetworkError) as context_manager:
            l4_client.init_connection()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)

        l4_client.close()
        test_http_proxy_server.kill()
        test_http_server.kill()

    def test_receive(self):
        address = 'smtp.gmail.com'
        _, result = self._create_client_and_receive_text(address, 587, 4 + len(address))
        self.assertEqual(result, '220 ' + address)

    def test_receive_until(self):
        address = 'smtp.gmail.com'

        l4_client = L4ClientTCP(address, 587)
        l4_client.init_connection()
        with self.assertRaises(StopIteration):
            l4_client.receive_until(terminator=b'\r\n', max_line_length=3)
        self.assertEqual(b'220', l4_client.buffer)
        l4_client.receive_until(terminator=b'\r\n')
        self.assertEqual(l4_client.buffer[-2:], b'\r\n')
        self.assertTrue(l4_client.buffer.decode('ascii').startswith('220 ' + address))

        l4_client.close()

    def test_real(self):
        test_http_server = TestThreadedServerHttp('127.0.0.1', 0)
        test_http_server.init_connection()
        test_http_server.start()

        l4_client = L4ClientTCP('127.0.0.1', test_http_server.bind_port)
        l4_client.init_connection()
        request = b'\r\n'.join([
            b'GET / HTTP/1.1',
            b'Host: 127.0.0.1',
            b'',
            b''
        ])
        request_len = l4_client.send(request)
        self.assertEqual(request_len, len(request))

        l4_client.receive_line()
        self.assertEqual(l4_client.buffer.strip(), b'HTTP/1.0 200 OK')

        l4_client.flush_buffer()
        l4_client.receive_line()
        self.assertEqual(l4_client.buffer.strip(), b'Server: TestHTTPRequestHandler')

        l4_client.flush_buffer()
        l4_client.receive_line()
        self.assertEqual(l4_client.buffer.strip(), b'Date: Thu, 01 Jan 1970 00:00:00 GMT')

        l4_client.flush_buffer()
        l4_client.receive_line()
        self.assertTrue(l4_client.buffer.startswith(b'Content-type: text/html; charset='))

        l4_client.flush_buffer()
        l4_client.receive_line()
        self.assertTrue(l4_client.buffer.startswith(b'Content-Length: 1'))

        l4_client.flush_buffer()
        l4_client.receive_line()
        self.assertEqual(l4_client.buffer.strip(), b'')

        l4_client.close()

        test_http_proxy_server = TestThreadedServerHttpProxy('127.0.0.2', 0)
        test_http_proxy_server.init_connection()
        test_http_proxy_server.start()

        http_proxy_url = urllib3.util.parse_url(f'http://127.0.0.2:{test_http_proxy_server.bind_port}')

        l4_client = L4ClientTCP(
            '127.0.0.1', test_http_server.bind_port,
            socket_params=L4TransferSocketParams(http_proxy=http_proxy_url)
        )
        l4_client.init_connection()

        request = b'\r\n'.join([
            b'GET / HTTP/1.1',
            b'Host: 127.0.0.1',
            b'',
            b''
        ])
        request_len = l4_client.send(request)
        self.assertEqual(request_len, len(request))

        l4_client.receive_line()
        self.assertEqual(l4_client.buffer.strip(), b'HTTP/1.0 200 OK')

        l4_client.close()

        test_http_proxy_server.kill()
        test_http_server.kill()


class L4ServerEcho(TestThreadedServer):
    def __init__(self, l4_server):
        super().__init__(l4_server)

        self.killed = False

    def kill(self):
        self.killed = True

    def run(self):
        while not self.killed:
            self._server.accept()
            while True:
                try:
                    self._server.receive(1)
                except NotEnoughData:
                    break
                except NotImplementedError:
                    self.killed = True
                    break

            if self._server.buffer:
                self._server.send(self._server.buffer)
                self._server.flush_buffer()


class TestL4ServerTCP(unittest.TestCase):
    @mock.patch.object(socket.socket, 'listen', side_effect=KeyboardInterrupt)
    def test_error_keyboard_interrupt(self, _):
        l4_server = L4ServerTCP('localhost', 0)
        with self.assertRaises(NetworkError) as context_manager:
            l4_server.init_connection()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)
        l4_server.close()

    def test_error_wrong_port(self):
        l4_server = L4ServerTCP('localhost', 65536)
        with self.assertRaises(NetworkError) as context_manager:
            l4_server.init_connection()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)
        l4_server.close()

    def test_error_wrong_address(self):
        l4_server = L4ServerTCP('8.8.8.8', 443)
        with self.assertRaises(NetworkError) as context_manager:
            l4_server.init_connection()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)
        l4_server.close()

    def test_bind_parameters(self):
        l4_server = L4ServerTCP('127.0.0.1', 1234)
        l4_server.init_connection()
        self.assertEqual(l4_server.bind_address, '127.0.0.1')
        self.assertEqual(l4_server.bind_port, 1234)

        l4_server = L4ServerTCP('::1', 0)
        l4_server.init_connection()
        self.assertEqual(l4_server.bind_address, '::1')
        self.assertNotEqual(l4_server.bind_port, 0)

    def test_no_data_sent(self):
        l4_server = L4ServerTCP('localhost', 0)
        threaded_server = L4ServerEcho(l4_server)
        threaded_server.start()

        threaded_server.kill()

        l4_client = L4ClientTCP('localhost', l4_server.bind_port)
        l4_client.init_connection()

        with self.assertRaises(NotEnoughData) as context_manager:
            l4_client.receive(1)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        threaded_server.kill()
        threaded_server.join()

    def test_echo(self):
        l4_server = L4ServerTCP('localhost', 0)
        threaded_server = L4ServerEcho(l4_server)
        threaded_server.wait_for_server_listen()

        threaded_server.kill()

        l4_client = L4ClientTCP('localhost', l4_server.bind_port)
        l4_client.init_connection()
        l4_client.send(b'echo')
        l4_client.receive(4)
        self.assertEqual(l4_client.buffer, b'echo')
        l4_client.close()

        threaded_server.join()


class TestL4ServerUDP(unittest.TestCase):
    def test_error_wrong_port(self):
        l4_server = L4ServerUDP('localhost', 65536)
        with self.assertRaises(NetworkError) as context_manager:
            l4_server.init_connection()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)
        l4_server.close()

    def test_error_wrong_address(self):
        l4_server = L4ServerUDP('8.8.8.8', 443)
        with self.assertRaises(NetworkError) as context_manager:
            l4_server.init_connection()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)
        l4_server.close()

    def test_error_multiple_clients(self):
        l4_server = L4ServerUDP('localhost', 0)
        threaded_server = L4ServerEcho(l4_server)
        threaded_server.start()

        l4_client = L4ClientUDP('localhost', l4_server.bind_port)
        l4_client.init_connection()
        l4_client.send(b'echo')
        l4_client.close()

        l4_client = L4ClientUDP('localhost', l4_server.bind_port)
        l4_client.init_connection()
        l4_client.send(b'echo')
        l4_client.close()

        threaded_server.join(1)
        self.assertTrue(threaded_server.killed)

    def test_bind_parameters(self):
        l4_server = L4ServerUDP('127.0.0.1', 1234)
        l4_server.init_connection()
        self.assertEqual(l4_server.bind_address, '127.0.0.1')
        self.assertEqual(l4_server.bind_port, 1234)

        l4_server = L4ServerUDP('::1', 0)
        l4_server.init_connection()
        self.assertEqual(l4_server.bind_address, '::1')
        self.assertNotEqual(l4_server.bind_port, 0)

    def test_echo(self):
        l4_server = L4ServerUDP('localhost', 0)
        threaded_server = L4ServerEcho(l4_server)
        threaded_server.wait_for_server_listen()

        l4_client = L4ClientUDP('localhost', l4_server.bind_port)
        l4_client.init_connection()
        l4_client.send(b'echo')
        l4_client.receive(4)
        self.assertEqual(l4_client.buffer, b'echo')
        l4_client.close()

        threaded_server.kill()
        threaded_server.join()
