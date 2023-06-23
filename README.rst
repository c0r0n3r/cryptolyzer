**CryptoLyzer** is a fast and flexible server cryptographic settings analyzer library for Python with an easy-to-use
`command line interface <https://en.wikipedia.org/wiki/Command-line_interface>`__ with both human-readable
(`Markdown <https://en.wikipedia.org/wiki/Markdown>`__) and
machine-readable (`JSON <https://en.wikipedia.org/wiki/JSON>`__) output.  It works with multiple cryptographic protocols
(`SSL <https://en.wikipedia.org/wiki/Transport_Layer_Security#SSL_1.0,_2.0,_and_3.0>`__/
`TLS <https://en.wikipedia.org/wiki/Transport_Layer_Security>`__,
`opportunistic TLS <https://en.wikipedia.org/wiki/Opportunistic_TLS>`__,
`SSH <https://en.wikipedia.org/wiki/Secure_Shell>`__) and analyzes additional security mechanisms
(`web security <https://infosec.mozilla.org/guidelines/web_security>`__ related
`HTTP response header fields <https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#Response_fields>`__,
`JA3 tag <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`__) or `HASSH
tag <https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c/>`__).

Usage
-----

Pip
^^^

.. code:: shell

   pip install cryptolyzer

   cryptolyze tls all www.example.com
   cryptolyze tls1_2 ciphers www.example.com
   cryptolyze ssh2 ciphers www.example.com
   cryptolyze http headers www.example.com

Docker
^^^^^^

.. code:: shell

   docker run --rm coroner/cryptolyzer tls all www.example.com
   docker run --rm coroner/cryptolyzer tls1_2 ciphers www.example.com
   docker run --rm coroner/cryptolyzer ssh2 ciphers www.example.com
   docker run --rm coroner/cryptolyzer http headers www.example.com

.. code:: shell

   docker run -ti --rm -p 127.0.0.1:4433:4433 coroner/cryptolyzer ja3 generate 127.0.0.1:4433
   openssl s_client -connect 127.0.0.1:4433

   docker run -ti --rm -p 127.0.0.1:2121:2121 coroner/cryptolyzer ja3 generate ftp://127.0.0.1:2121
   openssl s_client -starttls ftp -connect 127.0.0.1:2121

.. code:: shell

   docker run -ti --rm -p 127.0.0.1:2222:4433 coroner/cryptolyzer hassh generate 127.0.0.1:2222
   openssl s_client -connect 127.0.0.1:2222

Support
-------

Python implementation
^^^^^^^^^^^^^^^^^^^^^

-  CPython (2.7, 3.3+)
-  PyPy (2.7, 3.5+)

Operating systems
^^^^^^^^^^^^^^^^^

-  Linux
-  macOS
-  Windows

Social Media
------------

-  `Twitter <https://twitter.com/CryptoLyzer>`__
-  `Facebook <https://www.facebook.com/cryptolyzer>`__

Credits
-------

Icons made by `Freepik <https://www.flaticon.com/authors/freepik>`__ from `Flaticon <https://www.flaticon.com/>`__.

License
-------

The code is available under the terms of Mozilla Public License Version 2.0 (MPL 2.0).

A non-comprehensive, but straightforward description of MPL 2.0 can be found at
`Choose an open source license <https://choosealicense.com/licenses#mpl-2.0>`__ website.

Credits
-------

-  `NLnet Foundation <https://nlnet.nl>`__ and `NGI Assure <https://www.assure.ngi.eu>`__, supports the project part of
   the `Next Generation Internet <https://ngi.eu>`__ initiative.
