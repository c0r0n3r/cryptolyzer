CryptoLyzer
===========

What is it and what is it not?
------------------------------

As the project name CryptoLyzer implies, it is a cryptographic protocol analyzer. The main purpose of creating this
application is the fact, that cryptography protocol analysis differs in many aspect from establishing a connection
using a cryptographic protocol. Analysis is mostly testing where we trigger special and corner cases of the protocol
and we also trying to establish connection with hardly supported, experimental, obsoleted or even deprecated mechanisms
or algorithms which are may or may not supported by the latest or any version of an implementation of the cryptographic 
protocol.

As follows, it is neither a comprehensive nor a secure client/server implementation of any cryptographic protocol. On 
the one hand analyzer implements only the absolutely necessary parts of the protocol to interact with servers. On the 
other it may use completely insecure algorithms and mechanisms. It is not designed and contraindicated to use these
client/server implementations establishing secure connections. If you are searching for proper cryptographic protocol 
implementations, there are several existing wrappers and native implementations for Python (eg: M2Crypto, pyOpenSSL, 
Paramiko, ...).

Quick start
-----------

CryptoLyzer can be installed directly via pip

::

    pip install cryptolyzer
    cryptolyzer tls ciphers www.example.com

or can be used via docker

::

    docker pull coroner/cryptolyzer
    docker run coroner/cryptolyzer tls ciphers www.example.com

Development environment
^^^^^^^^^^^^^^^^^^^^^^^

If you want to setup a development environment, you are in need of `pipenv <https://docs.pipenv.org/>`__.

::

    $ cd cryptolyzer
    $ pipenv install --dev
    $ pipenv shell

Generic Features
----------------

Protocols
^^^^^^^^^

SSL/TLS
"""""""

* transport layer

  * Secure Socket Layer (SSL)
  
    * `SSL 2.0 <https://tools.ietf.org/html/draft-hickman-netscape-ssl-00>`_
    * `SSL 3.0 <https://tools.ietf.org/html/rfc6101>`_
  
  * Transport Layer Security (TLS)
  
    * `TLS 1.0 <https://tools.ietf.org/html/rfc2246>`_
    * `TLS 1.1 <https://tools.ietf.org/html/rfc4346>`_
    * `TLS 1.2 <https://tools.ietf.org/html/rfc5246>`_

* application layer

  * `opportunistic TLS <https://en.wikipedia.org/wiki/Opportunistic_TLS>`_ (STARTTLS)

    * `IMAP <https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol>`_
    * `POP3 <https://en.wikipedia.org/wiki/Post_Office_Protocol>`_
    * `SMTP <https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`_

Analyzers
^^^^^^^^^

.. table:: Supported analyzers by cryptographic protocol versions

    +------------------------------------------+---------------------------------------+
    ||                                         | **Protocos**                          |
    ||                                         +---------------+-----------------------+
    ||                                         | *SSL*         | *TLS*                 |
    ||                                         +-------+-------+-------+-------+-------+
    || **Analyzers**                           |  2.0  |  3.0  |  1.0  |  1.1  |  1.2  |
    +==========================================+=======+=======+=======+=======+=======+
    | Cipher Suites (``ciphers``)              |   ✓   |   ✓   |   ✓   |   ✓   |   ✓   |
    +------------------------------------------+-------+-------+-------+-------+-------+
    | X.509 Public Keys (``pubkeys``)          |   ✓   |   ✓   |   ✓   |   ✓   |   ✓   |
    +------------------------------------------+-------+-------+-------+-------+-------+
    | Elliptic Curves (``curves``)             |  n/a  |  n/a  |   ✓   |   ✓   |   ✓   |
    +------------------------------------------+-------+-------+-------+-------+-------+
    | Diffie-Hellman parameters (``dhparams``) |  n/a  |  n/a  |   ✓   |   ✓   |   ✓   |
    +------------------------------------------+-------+-------+-------+-------+-------+
    | Signature Algorithms (``sigalgos``)      |  n/a  |  n/a  |  n/a  |   ✓   |   ✓   |
    +------------------------------------------+-------+-------+-------+-------+-------+

Python implementation
^^^^^^^^^^^^^^^^^^^^^

* CPython (2.7, >=3.3)
* PyPy (2.7, 3.5)

Operating systems
^^^^^^^^^^^^^^^^^

* Linux
* macOS
* Windows

Protocol Specific Features
--------------------------

Transport Layer Security (TLS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Only features that cannot be or difficultly implemented by the most popular SSL/TLS implementations (eg:
`GnuTls <https://www.gnutls.org/>`_, `LibreSSL <https://www.libressl.org/>`_, `OpenSSL <https://www.openssl.org/>`_,
`wolfSSL <https://www.wolfssl.com/>`_, ...) are listed.

Cipher Suites
"""""""""""""

#. supports each cipher suites discussed on `ciphersuite.info <https://ciphersuite.info>`_

License
-------

The code is available under the terms of Mozilla Public License Version 2.0 (MPL 2.0).

A non-comprehensive, but straightforward description of MPL 2 can be found at `Choose an open source
license <https://choosealicense.com/licenses#mpl-2.0>`__ website.
