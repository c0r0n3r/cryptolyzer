# -*- coding: utf-8 -*-

import select
import socket
import unittest

from test.common.classes import TestThreadedServer

import six

try:
    from unittest import mock
except ImportError:
    import mock

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4ClientTCP, L4ServerTCP


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

    def test_error_on_close(self):
        address = 'smtp.gmail.com'
        l4_client, _ = self._create_client_and_receive_text(address, 587, 4 + len(address), to_be_closed=False)
        sock = l4_client._socket  # pylint: disable=protected-access
        with mock.patch.object(socket.socket, 'close', side_effect=socket.error):
            l4_client.close()
        sock.close()

    @unittest.skipIf(six.PY2, 'There is no ConnectionRefusedError in Python < 3.0')
    def test_error_connection_refused(self):
        with mock.patch.object(socket, 'create_connection', side_effect=ConnectionRefusedError), \
                self.assertRaises(NetworkError) as context_manager:
            l4_client = L4ClientTCP('badssl.com', 443)
            l4_client.init_connection()
        l4_client.close()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @unittest.skipIf(six.PY3, 'ConnectionRefusedError is raised instead of socket.error in Python >= 3.0')
    def test_error_connection_refused_socket_error(self):
        with mock.patch.object(socket, 'create_connection', side_effect=socket.error), \
                self.assertRaises(NetworkError) as context_manager:
            l4_client, _ = self._create_client_and_receive_text('badssl.com', 443, 1)
            l4_client.close()
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_error_unhandled_exception_rethrown(self):
        with mock.patch.object(socket, 'create_connection', side_effect=NotImplementedError), \
                self.assertRaises(NotImplementedError):
            self._create_client_and_receive_text('badssl.com', 443, 1)

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


class L4ServerTCPEcho(TestThreadedServer):
    def __init__(self, l4_server):
        super(L4ServerTCPEcho, self).__init__(l4_server)

        self.killed = False

    def kill(self):
        self.killed = True

    def run(self):
        readers = [self._server._server_socket]  # pylint: disable=protected-access
        writers = []

        while not self.killed:
            read, write, _ = select.select(readers, writers, readers, 1)
            for sock in read:
                if sock is self._server._socket:  # pylint: disable=protected-access
                    client_socket, _ = self._server._socket.accept()  # pylint: disable=protected-access
                    readers.append(client_socket)
                else:
                    self._server.receive(1)

            if self._server.buffer:
                for sock in write:
                    self._server.send(self._server.buffer)
                self._server.flush_buffer(1)
            elif len(readers) > 1:
                del readers[-1]

        for sock in readers:
            sock.close()


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

    def test_port(self):
        l4_server = L4ServerTCP('localhost', 1234)
        self.assertEqual(l4_server.port, 1234)

    def test_echo(self):
        l4_server = L4ServerTCP('localhost', 0)
        threaded_server = L4ServerTCPEcho(l4_server)
        threaded_server.wait_for_server_listen()

        self.assertEqual(l4_server.port, 0)
        self.assertNotEqual(l4_server.bind_port, 0)
        threaded_server.kill()
        threaded_server.join()

    def test_count(self):
        l4_client = L4ClientTCP('httpbin.org', 80)
        l4_client.init_connection()
        request = b'\r\n'.join([
            b'GET /base64/SFRUUEJJTiBpcyBhd2Vzb21l HTTP/1.1',
            b'Host: httpbin.org',
            b'',
            b''
        ])
        request_len = l4_client.send(request)
        self.assertEqual(request_len, len(request))

        response = b'HTTPBIN is awesome'
        response_len = l4_client.receive(len(response))
        self.assertEqual(response_len, len(response))

        l4_client.close()
