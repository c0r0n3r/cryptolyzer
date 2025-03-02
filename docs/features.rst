--------
Features
--------

SSH
^^^

Differentiators
"""""""""""""""

-  checks supported Diffie-Hellman (group exchange) key sizes
-  checks supported host certificates, X.509 certificates and chains
-  analyzes server protocol version string to identify application server vendor and version

Versions
""""""""

-  `SSH 2.0 <https://tools.ietf.org/html/rfc4253>`__

Analyzers
"""""""""

Supported analyzers by cryptographic protocol versions

+-------------------------------------------------------------+---------+
| Analyzers                                                   | SSH 2.0 |
+=============================================================+=========+
| Cipher Suites (``ciphers``)                                 |    ✓    |
+-------------------------------------------------------------+---------+
| Diffie-Hellman parameters (``dhparams``)                    |    ✓    |
+-------------------------------------------------------------+---------+
| Host Keys, Host/X.509 Certificates and Chains (``pubkeys``) |    ✓    |
+-----------------------------------------------------------------------+
| Vulnerabilities (``vulns``)                                 |    ✓    |
+-------------------------------------------------------------+---------+

Vulnerabilities
"""""""""""""""

-  `D(HE)at attack <https://dheatattack.gitlab.io/>`__
-  `Terrapin attack <https://terrapin-attack.com/>`__
-  `Logjam attack <https://weakdh.org/>`__
-  `RC4 ciphers <https://en.wikipedia.org/wiki/RC4#Security>`__
-  `Sweet32 attack <https://sweet32.info/>`__
-  `anonymous Diffie-Hellman ciphers <https://en.wikipedia.org/wiki/Key-agreement_protocol#Exponential_key_exchange>`__
-  `early SSH versions <https://en.wikipedia.org/wiki/Secure_Shell#SSH-1>`__
-  `non-forward-secret ciphers <https://en.wikipedia.org/wiki/Forward_secrecy>`__
-  `null encryption ciphers <https://en.wikipedia.org/wiki/Null_encryption>`__

SSL/TLS
^^^^^^^

Differentiators
"""""""""""""""

-  checks 10+ application layer protocols with `opportunistic TLS <https://en.wikipedia.org/wiki/Opportunistic_TLS>`__
   capability
-  checks 400+ cipher suites, more than discussed on `ciphersuite.info <https://ciphersuite.info>`__, or supported by
   `GnuTls <https://www.gnutls.org>`__, `LibreSSL <https://www.libressl.org>`__, `OpenSSL <https://www.openssl.org>`__,
   or `wolfSSL <https://www.wolfssl.com>`__
-  checks `GOST <https://en.wikipedia.org/wiki/GOST>`__ (national standards of the Russian Federation and CIS countries)
   cipher suites
-  checks `post-quantum <https://en.wikipedia.org/wiki/Post-quantum_cryptography>`__ elliptic curves
   (`Kyber <https://en.wikipedia.org/wiki/Kyber>`__)
-  checks TLS 1.3 draft versions, not just finnal version
-  checks whether Diffie-Hellman

   -  public parameter is a `safe prime <https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes>`__
   -  public parameter is defined in an RFC (e.g., FFDHE, MODP) or used by an application server as a builtin parameter
   -  key exchange supports `RFC 7919 <https://www.rfc-editor.org/rfc/rfc7919.html>`__ (FFDHE)
   -  key is `reused <https://security.stackexchange.com/questions/225209/what-is-ecdh-public-server-param-reuse>`__

Analyzers
"""""""""

Supported analyzers by cryptographic protocol versions

+-------------------------------------------+-----+-----+-----+-----+-----+-----+
| Analyzers                                 |    SSL    |          TLS          |
+-------------------------------------------+-----+-----+-----+-----+-----+-----+
|                                           | 2.0 | 3.0 | 1.0 | 1.1 | 1.2 | 1.3 |
+===========================================+=====+=====+=====+=====+=====+=====+
| Cipher Suites  (``ciphers``)              |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |
+-------------------------------------------+-----+-----+-----+-----+-----+-----+
| X.509 Public Keys (``pubkeys``)           |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |  ✗  |
+-------------------------------------------+-----+-----+-----+-----+-----+-----+
| X.509 Public Keys Request (``pubkeyreq``) | n/a |  ✓  |  ✓  |  ✓  |  ✓  |  ✗  |
+-------------------------------------------+-----+-----+-----+-----+-----+-----+
| Diffie-Hellman parameters (``dhparams``)  | n/a |  ✓  |  ✓  |  ✓  |  ✓  |  ✓  |
+-------------------------------------------+-----+-----+-----+-----+-----+-----+
| Elliptic-Curves (``curves``)              | n/a | n/a |  ✓  |  ✓  |  ✓  |  ✓  |
+-------------------------------------------+-----+-----+-----+-----+-----+-----+
| Signature Algorithms (``sigalgos``)       | n/a | n/a | n/a |  ✓  |  ✓  |  ✓  |
+-------------------------------------------+-----+-----+-----+-----+-----+-----+
| Extensions (``extensions``)               | n/a | n/a | n/a | n/a |  ✓  |  ✓  |
+-------------------------------------------+-----+-----+-----+-----+-----+-----+
| Vulnerabilities (``vulns``)               | n/a | n/a | n/a | n/a | n/a | n/a |
+-------------------------------------------+-----+-----+-----+-----+-----+-----+
| Simulations (``simulations``)             | n/a | n/a | n/a | n/a | n/a | n/a |
+-------------------------------------------+-----+-----+-----+-----+-----+-----+

`Opportunistic TLS <https://en.wikipedia.org/wiki/Opportunistic_TLS>`__ or STARTTLS) which is an extension of an application
layer protocol -- offering a way to upgrade a plain text connection to an encrypted ione without using a separate port - is
supported in the case of the following application layer protocols.

   -  `FTP <https://en.wikipedia.org/wiki/File_Transfer_Protocol>`__
   -  `IMAP <https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol>`__
   -  `LDAP <https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol>`__
   -  `LMTP <https://en.wikipedia.org/wiki/Local_Mail_Transfer_Protocol>`__
   -  `MySQL <https://en.wikipedia.org/wiki/MySQL>`__
   -  `NNTP <https://en.wikipedia.org/wiki/Network_News_Transfer_Protocol>`__
   -  `OpenVPN <https://en.wikipedia.org/wiki/OpenVPN>`__
   -  `POP3 <https://en.wikipedia.org/wiki/Post_Office_Protocol>`__
   -  `PostgreSQL <https://en.wikipedia.org/wiki/PostgreSQL>`__
   -  `RDP <https://en.wikipedia.org/wiki/Remote_Desktop_Protocol>`__
   -  `Sieve <https://en.wikipedia.org/wiki/Sieve_(mail_filtering_language)>`__
   -  `SMTP <https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   -  `XMPP (Jabber) <https://en.wikipedia.org/wiki/XMPP>`__

Versions
""""""""

-  Transport Layer

   -  Secure Socket Layer (SSL)

      -  `SSL 2.0 <https://tools.ietf.org/html/draft-hickman-netscape-ssl-00>`__
      -  `SSL 3.0 <https://tools.ietf.org/html/rfc6101>`__

   -  Transport Layer Security (TLS)

      -  `TLS 1.0 <https://tools.ietf.org/html/rfc2246>`__
      -  `TLS 1.1 <https://tools.ietf.org/html/rfc4346>`__
      -  `TLS 1.2 <https://tools.ietf.org/html/rfc5246>`__
      -  `TLS 1.3 <https://tools.ietf.org/html/rfc8446>`__

Curves
""""""

-  check `post-quantum <https://en.wikipedia.org/wiki/Post-quantum_cryptography>`__ (PQC) algorithms

   | ``KYBER_512_R3``, ``KYBER_768_R3``, ``KYBER_1024_R3``,
   | ``SECP256R1_KYBER_512_R3``, ``SECP256R1_KYBER_768_R3``,
   | ``SECP384R1_KYBER_768_R3``, ``SECP521R1_KYBER_1024_R3``,
   | ``SECP256R1_ML_KEM_768``,
   | ``X25519_KYBER_512_R3``, ``X25519_KYBER_768_R3``,
   | ``X25519_KYBER_512_R3_CLOUDFLARE``,
   | ``X25519_KYBER_768_R3_CLOUDFLARE``,
   | ``X25519_ML_KEM_768``

Extensions
""""""""""

-  `application-layer protocol negotiation <https://www.rfc-editor.org/rfc/rfc5077.html>`__
-  `encrypt-then-MAC <https://www.rfc-editor.org/rfc/rfc7366.html>`__
-  `extended master secret <https://www.rfc-editor.org/rfc/rfc7627.html>`__
-  `next protocols negotiation <https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html>`__
-  `renegotiation indication <https://www.rfc-editor.org/rfc/rfc5746.html>`__
-  `session ticket <https://www.rfc-editor.org/rfc/rfc5077.html>`__
-  `inetrnal clock accuracy <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2>`__

Public Keys
"""""""""""

-  validation against notable trusted root CA certificates stores

   -  `Apple <https://en.wikipedia.org/wiki/Apple_Inc.>`__
   -  `Google <https://en.wikipedia.org/wiki/Google>`__
   -  `Microsoft <https://en.wikipedia.org/wiki/Microsoft>`__
   -  `Mozilla <https://en.wikipedia.org/wiki/Mozilla>`__

-  revocation check

   -  `certificate Revocation List (CRL) <https://www.rfc-editor.org/info/rfc5280>`__
   -  `certificate status (OCSP, OCSP stapling) <https://www.rfc-editor.org/info/rfc6960>`__

-  extensions

   -  `TLS feature <https://www.rfc-editor.org/info/rfc7633>`__ (e.g. OCSP must staple)
   -  `extended validation <https://en.wikipedia.org/wiki/Extended_Validation_Certificate>`__

-  `certificate transparency (CT) <https://www.rfc-editor.org/info/rfc6962>`__

   - timestamp information
   - transparency log information

Vulnerabilities
"""""""""""""""

-  `D(HE)at attack <https://dheatattack.gitlab.io/>`__
-  `DROWN attack <https://drownattack.com/>`__
-  `FREAK attack <https://en.wikipedia.org/wiki/FREAK>`__
-  `Logjam attack <https://weakdh.org/>`__
-  `Lucky Thirteen attack <https://en.wikipedia.org/wiki/Lucky_Thirteen_attack>`__
-  `RC4 ciphers <https://en.wikipedia.org/wiki/RC4#Security>`__
-  `Sweet32 attack <https://sweet32.info/>`__
-  `anonymous Diffie-Hellman ciphers <https://en.wikipedia.org/wiki/Key-agreement_protocol#Exponential_key_exchange>`__
-  `inappropriate version fallback <https://www.rfc-editor.org/rfc/rfc7507.html>`__
-  `early TLS versions <https://www.rfc-editor.org/rfc/rfc8996>`__
-  `insecure SSL versions <ihttps://www.rfc-editor.org/rfc/rfc7507.html>`__
-  `export grade ciphers <https://en.wikipedia.org/wiki/Export_of_cryptography_from_the_United_States>`__
-  `non-forward-secret ciphers <https://en.wikipedia.org/wiki/Forward_secrecy>`__
-  `null encryption ciphers <https://en.wikipedia.org/wiki/Null_encryption>`__

Simulated Clients
"""""""""""""""""

-  TLS

   -  `Chromium <https://en.wikipedia.org/wiki/Chromium_(web_browser)>`__
   -  `Firefox <https://en.wikipedia.org/wiki/Firefox>`__
   -  `Opera <https://en.wikipedia.org/wiki/Opera_(web_browser)>`__

Fingerprinting
""""""""""""""

1. generates `JA3 tag <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`__ of any
   connecting TLS client independently from its type (graphical/cli, browser/email client/...)

   -  `FTP <https://en.wikipedia.org/wiki/File_Transfer_Protocol>`__
   -  `LDAP <https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol>`__
   -  `LMTP <https://en.wikipedia.org/wiki/Local_Mail_Transfer_Protocol>`__
   -  `MySQL <https://en.wikipedia.org/wiki/MySQL>`__
   -  `NNTP <https://en.wikipedia.org/wiki/Network_News_Transfer_Protocol>`__
   -  `OpenVPN <https://en.wikipedia.org/wiki/OpenVPN>`__
   -  `POP3 <https://en.wikipedia.org/wiki/Post_Office_Protocol>`__
   -  `PostgreSQL <https://en.wikipedia.org/wiki/PostgreSQL>`__
   -  `RDP <https://en.wikipedia.org/wiki/Remote_Desktop_Protocol>`__
   -  `Sieve <https://en.wikipedia.org/wiki/Sieve_(mail_filtering_language)>`__
   -  `SMTP <https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__

2. decodes existing `JA3 tags <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`__
   by showing human-readable format of the TLS parameters represented by the tag
3. generates `HASSH tag <https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c/>`__) of SSH clients

Hypertext Transfer Protocol (HTTP)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Analyzers
"""""""""

Headers
"""""""

-  generic headers

   -  `Content-Type <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type>`__
   -  `NEL <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/NEL>`__ (Network Error Logging)
   -  `Server <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server>`__
   -  `Set-Cookie <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>`__

-  caching headers

   -  `Age <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Age>`__
   -  `Cache-Control <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control>`__
   -  `Date <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date>`__
   -  `ETag <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag>`__
   -  `Expires <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires>`__
   -  `Last-Modified <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified>`__
   -  `Pragma <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma>`__

-  security headers

   -  `Content Security Policy <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>`__ (CSP)
   -  `Content-Security-Policy-Report-Only <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only>`__
   -  `Expect-CT <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT>`__
   -  `Expect-Staple <https://scotthelme.co.uk/designing-a-new-security-header-expect-staple>`__
   -  `HTTP Public Key Pinning <https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning>`__ (HPKP)
   -  `Referrer-Policy <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy>`__
   -  `Strict-Transport-Security <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security>`__
   -  `X-Content-Type-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>`__
   -  `X-Frame-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options>`__
   -  `X-XSS-Protection <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection>`__

-  content security

   -  `subresource integrity <https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity>`__
   -  `mixed content <https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content>`__

DNS
^^^

Differentiators
"""""""""""""""

-  extract (public key) and analyze (key type, size) DNSSEC signing keys

Analyzers
"""""""""

-  e-mail authentication, reporting related records

   -  `Domain-based Message Authentication, Reporting, and Conformance <https://www.rfc-editor.org/rfc/rfc7489>`__
      (DMARC)
   -  `Sender Policy Framework <https://www.rfc-editor.org/rfc/rfc7208>`__ (SPF)
   -  `SMTP MTA Strict Transport Security <https://www.rfc-editor.org/rfc/rfc8461>`__ (MTA-STS)
   -  `SMTP TLS Reporting <https://www.rfc-editor.org/rfc/rfc8460>`__ (TLSRPT)

-  `DNSSEC <https://www.rfc-editor.org/rfc/rfc4034>`__ records

   -  `DNSKEY <https://www.rfc-editor.org/rfc/rfc4034#section-2>`__
   -  `DS <https://www.rfc-editor.org/rfc/rfc4034#section-5>`__
   -  `RRSIG <https://www.rfc-editor.org/rfc/rfc4034#section-3>`__
