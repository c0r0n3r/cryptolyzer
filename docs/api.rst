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

SSH
===

By now, almost exclusively the 2.0 version of the SSH protocol is used in practice, as the 1.5 versions have many
security flaws. As a consequence CryptoLyzer supports only the 2.0 version of SSH, however, it can be recognized that a
server supports both SSH protocol versions 1 and 2.

Software and Protocol Version
-----------------------------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.ssh.versions import AnalyzerVersions
    >>> from cryptolyzer.ssh.client import L7ClientSsh
    >>>
    >>> analyzer = AnalyzerVersions()
    >>> client = L7ClientSsh('git.centos.org', 22)
    >>> result = analyzer.analyze(client)
    >>>
    >>> list(map(str, result.protocol_versions))
    ['SSH 2.0']
    >>>
    >>> result.software_version.vendor
    'OpenSSH'
    >>> result.software_version.version
    '8.0'

Result Classes
``````````````

.. automodule:: cryptolyzer.ssh.versions
    :members:

Cipher Suites
-------------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.ssh.pubkeys import AnalyzerCiphers
    >>> from cryptolyzer.ssh.client import L7ClientSsh
    >>>
    >>> analyzer = AnalyzerCiphers()
    >>> client = L7ClientSsh('github.com', 22)
    >>> result = analyzer.analyze(client)
    >>>
    >>> list(map(
    ... lambda public_key: public_key.host_key_algorithm.value.code,
    ... result.public_keys
    ... ))
    ['ecdsa-sha2-nistp256', 'ssh-ed25519', 'ssh-rsa']

Result Classes
``````````````

.. automodule:: cryptolyzer.ssh.ciphers
    :members:

Diffie-Hellman Parameters
-------------------------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.ssh.dhparams import AnalyzerDHParams
    >>> from cryptolyzer.ssh.client import L7ClientSsh
    >>>
    >>> analyzer = AnalyzerDHParams()
    >>> client = L7ClientSsh('git.launchpad.net', 22)
    >>> result = analyzer.analyze(client, protocol_version)
    >>>
    >>> list(map(
    ... lambda key_exchange: key_exchange.value.key_size,
    ... result.key_exchange.kex_algorithms
    ... ))
    [2048]
    >>>
    >>> result.group_exchange.key_sizes
    [2048, 3072, 4096, 6144, 7680, 8192]

Result Classes
``````````````

.. automodule:: cryptolyzer.ssh.dhparams
    :members:

Host Keys and Certificates
--------------------------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.ssh.pubkeys import AnalyzerPublicKeys
    >>> from cryptolyzer.ssh.client import L7ClientSsh
    >>>
    >>> analyzer = AnalyzerPublicKeys()
    >>> client = L7ClientSsh('git.launchpad.net', 22)
    >>> result = analyzer.analyze(client)
    >>>
    >>> list(map(
    ... lambda public_key: public_key.host_key_algorithm.value.code,
    ... result.public_keys
    ... ))
    ['ssh-rsa']
    >>>
    >>> print(result.public_keys[0].public_key.pem)
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxBURMAQ9sntl63NklXFJ
    pieODBdQQgd1tdTU2oqs1Y+12Z0JoFmZPVGnR1WNsAV73pXAzudTDzeaMyYxQJJ8
    NPaz+1zESTJQDi0iFaFOg0RdbtY/JCVWPnX4gx4Xku/rIgA565m/Bxp9sUEOhCQ4
    wF68NcefMeXmY0NDxVnSPqUU3WBr1pKR3VyhTumvf5Q8eLqPTAp3jxBov0J5Apiq
    iwgVJWDWWEYgfJ1XntrTBdJo1fMZNayfv1D/vPe/hVxUfcPwdRD0Y4kN+WTUGSjz
    +IrMT7cjLgkJGWO3JFq+WLMpTX7zXMhg5ztV2s2YSe9a8w6YtUZpxVwVuYvtnZts
    uwIDAQAB
    -----END PUBLIC KEY-----

Result Classes
``````````````

.. automodule:: cryptolyzer.ssh.pubkeys
    :members:

HTTP(S)
=======

By now, exclusively the 1.1 version of the HTTP protocol is used in practice, so CryptoLyzer supports only the 1.1
version of the HTTP protocol. The analyses work both with the plain text version of the protocol (HTTP) and the
TLS-secured version (HTTPS).

Headers
-------

Code Snippet
````````````

.. code:: python

    >>> from cryptolyzer.httpx.headers import AnalyzerHeaders
    >>> from cryptolyzer.httpx.client import L7ClientHttp
    >>>
    >>> analyzer = AnalyzerHeaders()
    >>> client = L7ClientHttp('https://hstspreload.org/')
    >>> result = analyzer.analyze(client, None)
    >>>
    >>> header = next(filter(
    ... lambda header: isinstance(header, HttpHeaderFieldSTS),
    ... result.headers
    ... ))
    >>>
    >>> header.value.preload.value
    True
    >>> header.value.max_age.value
    datetime.timedelta(days=365)


Result Classes
``````````````

.. automodule:: cryptolyzer.httpx.headers
    :members:

DNSSEC
======

Code Snippet
------------

.. code:: python

    >>> from cryptolyzer.dnsrec.dnssec import AnalyzerDnsSec
    >>> from cryptolyzer.dnsrec.client import L7ClientDns
    >>>
    >>> analyzer = AnalyzerDnsSec()
    >>> client = L7ClientDns('cloudflare.com')
    >>>
    >>> result = analyzer.analyze(client)
    >>>
    >>> list(map(
    ... lambda dns_key: set(map(lambda flag: flag.name, dns_key.flags)),
    ... result.dns_keys
    ... ))
    [{'DNS_ZONE_KEY'}, {'DNS_ZONE_KEY'}, {'SECURE_ENTRY_POINT', 'DNS_ZONE_KEY'}]
    >>>
    >>> list(map(
    ... lambda dns_key: dns_key.key_tag,
    ... result.dns_keys
    ... ))
    [43038, 32553, 57355]
    >>>
    >>> list(map(
    ... lambda digital_signature: digital_signature.key_tag,
    ... result.digital_signatures
    ... ))
    [57355]

Result Classes
--------------

.. automodule:: cryptolyzer.dnsrec.dnssec
    :members:
