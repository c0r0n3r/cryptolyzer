---------------------------------
Application Programming Interface
---------------------------------

CryptoLyzer is not only a command-line tool but also provides a Python API, making it possible to customize the analysis 
post-process its result or generate customized output by using a high-level, popular programming language. The main
concept of the analysis requires two objects, namely an analyzer and an analyzable. A special kind of client represents
the analyzable and implements the strictly necessary part of a certain protocol used by the analyzer to get the
relevant in terms of a certain analysis. Different types of protocol -- including opportunistic TLS protocols -- are
implemented by separate client types and different analysis types can also be run separately. However, a full analysis
can also be run at once just like using the command-line interface.

TLS
===

The TLS protocol was used in two ways in the application layer protocol. One case is that the secure layer
(TLS) initiated first and after it is successfully established the original application layer protocol (e.g. HTTP,
IMAP, ...), while in the second case, the application layer protocol (e.g.: SMTP, POP3, ...) has an extension, which
defines a command -- usually called ``STARTTLS`` -- that a client can use to initiate the secure channel. This second
way of working is called opportunistic TLS and requires different client implementations for the different application
layer protocols. CryptoLyzer supports all these protocols and also OpenVPN uses TLS to secure its command channel
wrapping the original TLS protocol.

.. code:: python

    from cryptolyzer.tls.client import L7ClientTls, ClientIMAP
    from cryptolyzer.tls.client import ClientOpenVpn, ClientOpenVpnTcp

    client = L7ClientTls(host, port)
    client = ClientIMAP(host, port)
    client = ClientOpenVpn(host, port)
    client = ClientOpenVpnTcp(host, port)

The TLS protocol always has some versions, meaning that just like in the command-line interface it is the parameter
of the analysis in the case of the Python API, whenever the analysis itself version-dependent. As mentioned in the
command-line interface there is some protocol version independent analysis. The most obvious one is the analysis of the
protocol version supported by a server. In those cases, the protocol version is omitted by the analyzer

.. code:: python

    >>> from cryptolyzer.tls.client import L7ClientTls
    >>> from cryptolyzer.tls.versions import AnalyzerVersions
    >>>
    >>> analyzer = AnalyzerVersions()
    >>> client = L7ClientTls('dh1024.badssl.com', 443)
    >>> result = analyzer.analyze(client, None)
    >>>
    >>> list(map(str, result.versions))
    ['TLS 1.0', 'TLS 1.1', 'TLS 1.2']
    >>>
    >>> from cryptolyzer.tls.dhparams import AnalyzerDHParams
    >>> from cryptodatahub.tls.version import TlsVersion
    >>> from cryptoparser.tls.version import TlsProtocolVersion
    >>>
    >>> analyzer = AnalyzerDHParams()
    >>> protocol_version = TlsProtocolVersion(TlsVersion.TLS1_2)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> result.dhparam.key_size
    1024

Of course, the different types of analyzers have different types of results, however, the analysis can be performed in
the same way as explained below assuming in the examples that a protocol version supported by the analyzable server is
stored in the ``protocol_version`` variable.

Vulnerabilities
---------------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.tls.vulnerabilities import AnalyzerVulnerabilities
    >>> from cryptolyzer.tls.client import L7ClientTls
    >>>
    >>> analyzer = AnalyzerVulnerabilities()
    >>> client = L7ClientTls('dh1024.badssl.com', 443)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> result.ciphers.lucky13
    True
    >>> result.versions.early_tls_version
    True
    >>> result.dhparams.logjam
    True

Result Classes
``````````````

.. automodule:: cryptolyzer.tls.vulnerabilities
    :members:

Cipher Suites
-------------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.tls.ciphers import AnalyzerCipherSuites
    >>> from cryptolyzer.tls.client import L7ClientTls
    >>>
    >>> analyzer = AnalyzerCipherSuites()
    >>> client = L7ClientTls('rc4-md5.badssl.com', 443)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> list(map(str, result.cipher_suites))
    ['TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5']

Result Classes
``````````````

.. automodule:: cryptolyzer.tls.ciphers
    :members:

Elliptic Curves
---------------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.tls.curves import AnalyzerCurves
    >>> from cryptolyzer.tls.client import L7ClientTls
    >>>
    >>> analyzer = AnalyzerCurves()
    >>> client = L7ClientTls('ecc256.badssl.com', 443)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> list(map(str, result.curves))
    ['TlsNamedCurve.SECP256R1']

Result Classes
``````````````

.. automodule:: cryptolyzer.tls.curves
    :members:

Diffie-Hellman Parameters
-------------------------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.tls.dhparams import AnalyzerDHParams
    >>> from cryptolyzer.tls.client import L7ClientTls
    >>>
    >>> analyzer = AnalyzerDHParams()
    >>> client = L7ClientTls('dh1024.badssl.com', 443)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> result.dhparam.key_size
    1024

Result Classes
``````````````

.. automodule:: cryptolyzer.tls.dhparams
    :members:

Certificate Chains
------------------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys
    >>> from cryptolyzer.tls.client import L7ClientTls
    >>>
    >>> analyzer = AnalyzerPublicKeys()
    >>> client = L7ClientTls('rsa2048.badssl.com', 443)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> certificate_chain = result.pubkeys[0].certificate_chain
    >>> leaf_certificate = certificate_chain.items[0]
    >>> leaf_certificate.key_type.name
    'RSA'
    >>>
    >>> client = L7ClientTls('ecc256.badssl.com', 443)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> certificate_chain = result.pubkeys[0].certificate_chain
    >>> leaf_certificate = certificate_chain.items[0]
    >>> leaf_certificate.key_type.name
    'ECDSA'

Result Classes
``````````````

.. automodule:: cryptolyzer.tls.pubkeys
    :members:

Signature Algorithms
--------------------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.tls.pubkeys import AnalyzerSigAlgos
    >>> from cryptolyzer.tls.client import L7ClientTls
    >>>
    >>> analyzer = AnalyzerSigAlgos()
    >>> client = L7ClientTls('rsa2048.badssl.com', 443)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> set(map(
    ... lambda sig_algo: sig_algo.value.signature_algorithm.name,
    ... result.sig_algos
    ... ))
    {'RSA'}
    >>>
    >>> client = L7ClientTls('ecc256.badssl.com', 443)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> set(map(
    ... lambda sig_algo: sig_algo.value.signature_algorithm.name,
    ... result.sig_algos
    ... ))
    {'ECDSA'}

Result Classes
``````````````

.. automodule:: cryptolyzer.tls.sigalgos
    :members:

Simulations
-----------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.tls.simulations import AnalyzerSimulations
    >>> from cryptolyzer.tls.client import L7ClientTls
    >>>
    >>> analyzer = AnalyzerSimulations()
    >>> client = L7ClientTls('rc4-md5.badssl.com', 443)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> set(map(
    ... lambda client: client.cipher_suite.name,
    ... result.succeeded_clients.values()
    ... ))
    {'TLS_RSA_WITH_RC4_128_MD5'}

Result Classes
``````````````

.. automodule:: cryptolyzer.tls.simulations
    :members:
