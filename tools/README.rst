Usage
-----

.. code:: shell

    tshark -r /path/to/handshake.pcap -d tcp.port==1-65535,tls -Y 'tls.handshake.type == 1' -T json | handshake_to_capabilities --protocol tls --format tshark | jq
