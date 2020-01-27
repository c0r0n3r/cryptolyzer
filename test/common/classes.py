# -*- coding: utf-8 -*-

import threading
import time


class TestThreaderServer(threading.Thread):
    def __init__(self, server):
        super(TestThreaderServer, self).__init__()

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
