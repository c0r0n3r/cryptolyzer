=========
Changelog
=========

-------------------
0.12.4 - 2024-04-28
-------------------

Notable fixes
=============

-  DNS (``dns``)

-  Generic

   -  handle CNAME records (#142)

-  TLS (``tls``)

   -  All (``all``)

      -  check curves using highest available version to recognize possibly supported PQC curves (#141)

   -  Simulations (``simulations``)

      -  consider protocol versions supported by the clients (#143)

-------------------
0.12.3 - 2024-03-05
-------------------

Features
========

-  TLS (``tls``)

   -  Versions (``versions``)

      -  add checker for inappropriate fallback alerts (#139)

   -  Vulnerabilities (``vulns``)

      -  add checker for insecure protocol versions (#137)
      -  add checker for inappropriate fallback alerts (#139)

Notable fixes
=============

-  TLS (``tls``)

   -  Ciphers (``ciphers``)

      - fix calculation of cipher suites relates to a certain version (#138)
      - fix cipher suite check when server does not support long cipher suite list (#135)

   -  Diffie-Hellman (``dhparams``)

      -  add missing SSLv3 support (#136)

   -  Vulnerabilities (``vulns``)

      -  fix calculation of missing forward secrecy (#134)

-------------------
0.12.2 - 2024-01-11
-------------------

Features
========

-  SSH (``ssh``)

   -  Vulnerabilities (``vulns``)

      -  checker for well-known vulnerabilities (#130)

         -  Sweet32 attack
         -  Anonymous Diffie-Hellman
         -  NULL encryption
         -  RC4
         -  Non-Forward-Secret
         -  Early SSH version
         -  Weak Diffie-Hellman
         -  DHEat attack
         -  Terrapin attack

Improvements
============

-  Generic

   -  add metadata to documentation


Notable fixes
=============

-  TLS (``tls``)

   -  Signature Algorithms (``sigalgos``)

      -  Handle decode error as a signal of no more algorithms. (#129)

-  DNS (``dns``)

   -  e-mail authentication, reporting (``mail``)

      -  Handle the case when a domain has no TXT records (#132)

-------------------
0.12.1 - 2023-12-13
-------------------

Notable fixes
=============

-  TLS

   -  All (``all``)

      -  handle server support only 1.3 version in ``all`` analyzer (#111)

   -  Simulations (``simulations``)

      -  fix markdown generation in the case of TLS client versions (#80)

   -  Generic

      -  avoid sending large records cause unexpected response from server (#127)

-  SSH

   -  Ciphers (``ciphers``)

      -  handle deprecated but not weak algorithms (#126)

Improvements
============

-  SSH

   -  handle deprecated but not weak algorithms (#126)

-------------------
0.12.0 - 2023-11-23
-------------------

Improvements
============

-  TLS (``tls``)

   -  Extensions (``extensions``)

      -  add analyzer checking which `record size limits <https://www.rfc-editor.org/rfc/rfc8449.html>`__ are supported
         (#123)

-------------------
0.11.2 - 2023-11-13
-------------------

Features
========

-  HTTP (``http``)

   -  Content (``content``)

      -  checker for subresource integrity (#86)
      -  checker for unencrypted content (#120)

Improvements
============

-  TLS (``tls``)

   -  Simulations (``simulations``)

      -  grade key exchange sizes (#121)

Notable fixes
=============

-  Generic

   -  handle not graded algorithms (#122)

-------------------
0.11.1 - 2023-11-06
-------------------

Features
========

-  TLS (``tls``)

   -  Elliptic Curves (``curves``)

      -  add support for post-quantum safe hybrid (Kyber) algorithms (#119)

-  SSH (``ssh``)

   -  Public Keys (``pubkeys``)

      -  X.509 certificate and certificate chain support (#70)

-------------------
0.11.0 - 2023-10-28
-------------------

Features
========

-  Generic

   -  colorized output based on the security strength of the cryptographic algorithms and key sizes (#94)
   -  documentation of command-line interface (#117)
   -  documentation of Python API (#117)

-------------------
0.10.3 - 2023-10-12
-------------------

Notable fixes
=============

-  Generic

   -  add missing dnsrec module to the packaging (#13)

-------------------
0.10.2 - 2023-08-28
-------------------

Features
========

-  DNS (``dns``)

   -  e-mail authentication, reporting (``mail``)

      -  add analyzer for `mail exchange <https://www.rfc-editor.org/rfc/rfc1035>`__ (MX) record (#115)
      -  add analyzer for e-mail authentication, reporting records (#116)

         -  `Domain-based Message Authentication, Reporting, and Conformance <https://www.rfc-editor.org/rfc/rfc7489>`__
            (DMARC)
         -  `Sender Policy Framework <https://www.rfc-editor.org/rfc/rfc7208>`__ (SPF)
         -  `SMTP MTA Strict Transport Security <https://www.rfc-editor.org/rfc/rfc8461>`__ (MTA-STS)
         -  `SMTP TLS Reporting <https://www.rfc-editor.org/rfc/rfc8460>`__ (TLSRPT)


-------------------
0.10.1 - 2023-08-29
-------------------

Features
========

-  DNS (``dns``)

   -  Domain Name System Security Extensions (``dnssec``)

      -  add analyzer for checking DNSSEC-related records (#95)

         -  `DNSKEY <https://www.rfc-editor.org/rfc/rfc4034#section-2>`__
         -  `DS <https://www.rfc-editor.org/rfc/rfc4034#section-5>`__
         -  `RRSIG <https://www.rfc-editor.org/rfc/rfc4034#section-3>`__

-------------------
0.10.0 - 2023-08-03
-------------------

Features
========

-  TLS (``tls``)

   -  Public Keys (``pubkeys``)

      -  validation against notable trusted root CA certificates stores (#91)

         -  `Apple <https://en.wikipedia.org/wiki/Apple_Inc.>`__
         -  `Google <https://en.wikipedia.org/wiki/Google>`__
         -  `Microsoft <https://en.wikipedia.org/wiki/Microsoft>`__
         -  `Mozilla <https://en.wikipedia.org/wiki/Mozilla>`__

      -  revocation check using soft-fail mechanism (#89)

      -  TLS feature (e.g. OCSP must staple) extension check (#87)

------------------
0.9.1 - 2023-06-22
------------------

Features
========

-  TLS (``tls``)

   -  Public Keys (``pubkeys``)

      -  certificate transparency (CT) log support (#47)

------------------
0.9.0 - 2023-04-29
------------------

Features
========

-  TLS (``tls``)

   -  Generic

      -  `OpenVPN <https://en.wikipedia.org/wiki/OpenVPN>`__ support (#85)

------------------
0.8.5 - 2023-04-02
------------------

Features
========

-  TLS (``tls``)

   -  Simulations (``simulations``)

      -  checker for client compatibility (#92)

         -  `Chromium <https://en.wikipedia.org/wiki/Chromium_(web_browser)>`__
         -  `Firefox <https://en.wikipedia.org/wiki/Firefox>`__
         -  `Opera <https://en.wikipedia.org/wiki/Opera_(web_browser)>`__

------------------
0.8.4 - 2023-01-22
------------------

Features
========

-  TLS (``tls``)

   -  Generic

      -  MySQL support (#54)

   -  Vulnerabilities (``vulns``)

      -  checker for well-known vulnerabilities (#93)

      -  Anonymous Diffie-Hellman
      -  DHEat attack
      -  DROWN attack
      -  Early TLS version
      -  Export grade ciphers
      -  FREAK attack
      -  Logjam attack
      -  Lucky Thirteen attack
      -  NULL encryption
      -  Non-Forward-Secret
      -  RC4
      -  Sweet32 attack

------------------
0.8.3 - 2022-11-06
------------------

Features
========

-  TLS (``tls``)

   -  Generic

   -  RDP hybrid mode support (#109)

------------------
0.8.2 - 2022-10-10
------------------

Features
========

-  Generic

   -  Diffie-Hellman

      -  add builtin Diffie-Hellman parameters of several application servers (#104)
      -  add logging support to make it possible to follow up the analysis process (#58)

-  SSH (``ssh``)

   -  HASSH (``hassh``)

      -  tag generation support for servers (#97)
      -  tag generation support for clients (#96)

   -  Public Keys (``pubkeys``)

      -  host certificate support (#69)

-  TLS (``tls``)

   -  Diffie-Hellman (``dhparams``)

      -  support finite field Diffie-Hellman ephemeral (FFDHE) parameter negotiation defined in RFC 7919 (#98)

Notable fixes
=============

-  TLS (``tls``)

   -  Extensions (``extensions``)

      -  Clock accuracy check works even if difference is negative (#103)

   -  Signature Algorithms (``sigalgos``)

      -  Not supported signature algorithms are not listed anymore (#102)

------------------
0.8.1 - 2022-03-23
------------------

Features
========

-  JA3 (``ja3``)

   -  Generate (``generate``)

      -  support NNTP clients (#83)
      -  support SMTP/LMTP clients (#82)
      -  support POP3 clients (#81)
      -  support FTP clients (#80)
      -  support Sieve clients (#79)
      -  support PostgreSQL clients (#78)
      -  support LDAP clients (#77)

------------------
0.8.0 - 2022-01-18
------------------

Features
========

-  SSH (``ssh``)

   -  Public Keys (``pubkeys``)

      -  add analyzer for checking SSH server against used
         `host keys <https://datatracker.ietf.org/doc/html/rfc4253#section-6.6>`__ (#34)

   -  Versions (``versions``)

      -  identify application server and version (#71)

------------------
0.7.3 - 2021-12-26
------------------

Features
========

-  SSH (``ssh``)

   -  Generic

      -  Add all command to SSH

Notable fixes
=============

-  Generic

   -  Diffie-Hellman

      -  Handle Diffie-Hellman parameter q value comparision well (#74)

-  TLS (``tls``)

   -  Generic

      -  Handle multi-line greeting message in the case of SMTP servers (#72)

   -  Diffie-Hellman (``dhparams``)

      -  Add safe prime attribute to well-known DH params as there is an RFC (5144) which defines unsafe prime (#73)

   -  Public Keys (``pubkeys``)

      -  Handle missing certificates message well during an anonymous Diffie-Hellman key exchange (#66)

------------------
0.7.2 - 2021-10-07
------------------

Features
========

-  SSH (``ssh``)

   -  Diffie-Hellman (``dhparams``)

      -  add group exchange algorithms supported by the server to the result (#53)

Other
=====

-  switch to Markdown format in changelog, readme and contributing
-  update contributing to the latest version from contribution-guide.org
-  add summary of the project to the readme

------------------
0.7.1 - 2021-09-20
------------------

Features
========

-  TLS (``tls``)

   -  LMTP opportunistic TLS (``STARTTLS``) support (#56)
   -  NNTP opportunistic TLS (``STARTTLS``) support (#7)
   -  PostgreSQL opportunistic TLS (``STARTTLS``) support (#55)

Notable fixes
=============

-  TLS (``tls``)

   -  Generic

      -  Use DH ephemeral keys that are mathematically correct during a TLS 1.3 handshake to increase stability (#57)

   -  Ciphers (``ciphers``)

      -  No fallback mechanism is used to check cipher suites if server honors long cipher suite lists (#59)

------------------
0.7.0 - 2021-09-02
------------------

Features
========

-  TLS (``tls``)

   -  Extensions (``extensions``)

      -  add analyzer checking which `application-layer protocols <https://www.rfc-editor.org/rfc/rfc5077.html>`__ are
         supported (#45)
      -  add analyzer checking whether `encrypt-then-MAC <https://www.rfc-editor.org/rfc/rfc7366.html>`__ mode is
         supported (#45)
      -  add analyzer checking whether `extended master secret <https://www.rfc-editor.org/rfc/rfc7627.html>`__ is
         supported (#45)
      -  add analyzer checking which `next protocols <https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html>`__
         are supported (#45)
      -  add analyzer checking whether `renegotiation indication <https://www.rfc-editor.org/rfc/rfc5746.html>`__ is
         supported (#45)
      -  add analyzer checking whether `session ticket <https://www.rfc-editor.org/rfc/rfc5077.html>`__ is supported
         (#45)

   -  Sieve opportunistic TLS (``STARTTLS``) support (#9)

-  SSH (``ssh``)

   -  Diffie-Hellman (``dhparams``)

      -  check which DH parameter sizes supported by the server by group exchange (#53)
      -  check which DH parameter sizes supported by the server by key exchange (#53)

Notable fixes
=============

-  TLS (``tls``)

   -  Generic

      -  handle server long cipher suite, signature algorithm list intolerance (#52)

------------------
0.6.0 - 2021-05-27
------------------

Improvements
============

-  TLS (``tls``)

   -  Ciphers (``ciphers``)

      -  add TLS 1.3 support (#35)

   -  Elliptic Curves (``curves``)

      -  add TLS 1.3 support (#35)

   -  Diffie-Hellman (``dhparams``)

      -  add TLS 1.3 support (#35)

   -  Signature Algorithms (``sigalgos``)

      -  add TLS 1.3 support (#35)

   -  Versions (``versions``)

      -  add TLS 1.3 support (#35)

------------------
0.5.0 - 2021-04-08
------------------

Features
========

-  TLS (``tls``)

   -  add analyzer (``all``) for running all TLS analysis at once (#40)

-  SSH (``ssh2``)

   -  add analyzer for checking SSH servers against
      `negotiated algorithms <https://tools.ietf.org/html/rfc4253#section-7.1>`__ (#33)

Usability
=========

-  Generic

   -  use human readable algorithms names in Markdown output (#48)
   -  command line interface gives error output instead of traceback on exception (#49)

------------------
0.4.0 - 2021-01-30
------------------

Features
========

-  TLS (``tls``)

   -  add analyzer for checking whether TLS server requires client certificate for authentication (#36)
   -  `LDAP <https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol>`__ support (#25)

Notable fixes
=============

-  TLS (``tls``)

   -  Generic

      -  handle that a server indicates handshake failure by sending close notify alert (#44)
      -  handle that a server does not respect lack of the signature algorithms extension (#43)

   -  Versions (``versions``)

      -  handle that a server supports only non-RSA public keys (#41)

Performance
===========

-  TLS (``tls``)

   -  Cipher Suites (``ciphers``)

      -  speed up TLS supported curve check (#39)

------------------
0.3.1 - 2020-09-15
------------------

Features
========

-  Generic

   -  `Markdown <https://en.wikipedia.org/wiki/Markdown>`__ output format (#30)

-  TLS (``tls``)

   -  `XMPP (Jabber) <https://en.wikipedia.org/wiki/XMPP>`__ support (#26)
   -  Cipher Suites (``ciphers``)

      -  `GOST <https://en.wikipedia.org/wiki/GOST>`__ (national standards of the Russian Federation and CIS countries)
         support for TLS cipher suite checker (#32)

Notable fixes
=============

-  TLS (``tls``)

   -  fix several uncertain test cases (#28)

Refactor
========

-  remove unnecessary unicode conversions (#29)
-  switch from `cryptography <https://cryptography.io>`__ to `certvalidator <https://github.com/wbond/certvalidator>`__

------------------
0.3.0 - 2020-04-30
------------------

Features
========

-  TLS (``tls``)

   -  RDP support (#21)

-  JA3 (``ja3``)

   -  `JA3 fingerprint <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`__
      decoding support (#22)
   -  `JA3 fingerprint <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`__
      generatoin support (#23)

Notable fixes
=============

-  FTP server check cause Python traceback on connection close (#27)

Refactor
========

-  use attrs to avoid boilerplates (#24)

------------------
0.2.0 - 2019-12-05
------------------

Features
========

-  TLS (``tls``)

   -  Diffie-Hellman (``dhparams``)

      -  check whether server uses `safe prime <https://en.wikipedia.org/wiki/Safe_prime>`__ as DH parameter to avoid
         `small subgroup confinement attack <https://en.wikipedia.org/wiki/Small_subgroup_confinement_attack>`__ (#13)
      -  check whether server uses well-known (RFC defined) DH parameter (#13)
      -  check whether server reuse the DH parameter (#13)

   -  FTP opportunistic TLS (``STARTTLS``) support (#8)

Notable Fixes
=============

-  TLS (``tls``)

   -  Cipher Suites (``ciphers``)

      -  handle server long cipher suite list intolerance
      -  fix cipher suite preference order calculation (#18)

   -  Elliptic Curves (``curves``)

      -  fix result when server does not support named group extension

   -  Public Keys (``pubkeys``)

      -  handle cross signed key in the certificate chain
      -  fix JSON output in case of expired certificates (#15)
      -  handle the case when only a self-singed CA is served as certificate (#17)
      -  handle the case when CA with no basic constraint is served (#20)

   -  handle rarely/incorrectly used TLS alerts
   -  handle when there is no response from server (#11)
   -  handle scheme other than tls in URL argument of the command line tool (#3)
   -  handle plain text response to TLS handshake initiation (#19)
   -  add default port for opportunistic TLS schemes (#6)
   -  uniform timeout handling in TLS clients (#12)

Other
=====

-  improve unit tests (100% code coverage)
-  Docker support and ready-to-use container on DockerHub
   (`coroner/cryprolyzer <https://hub.docker.com/r/coroner/cryptolyzer>`__)
-  build packages to several Linux distributions on `Open Build Service <https://build.opensuse.org/>`__

   -  Debian (10, Testing)
   -  Raspbian (10)
   -  Ubuntu (19.10)
   -  Fedora (29, 30, 31, Rawhide)
   -  Mageia (7, Cauldron)

-  IP address can be set to hostname in command line (#10)
-  fix several Python packaging issues

0.1.0 - 2019-03-20
------------------

Features
========

-  add analyzer for checking TLS server against supported
   `protocol versions <https://en.wikipedia.org/wiki/Transport_Layer_Security#History_and_development>`__
-  add analyzer for checking TLS server against supported
   `cipher suites <https://en.wikipedia.org/wiki/Cipher_suite>`__
-  add analyzer for checking TLS server against supported
   `elliptic curves <https://en.wikipedia.org/wiki/Elliptic-curve_cryptography>`__ types
-  add analyzer for checking TLS server against used
   `Diffie-Hellman parameters <https://wiki.openssl.org/index.php/Diffie-Hellman_parameters>`__
-  add analyzer for checking TLS server against supported signature algorithms
-  add analyzer for checking TLS server against used `X.509 <https://en.wikipedia.org/wiki/X.509>`__
   `public key certificates <https://en.wikipedia.org/wiki/Public_key_certificate>`__

Improvements
============

-  check TLS server against used fallback (handshake without
   `SNI <https://en.wikipedia.org/wiki/Server_Name_Indication>`__) certificates
-  add `opportunistic TLS <https://en.wikipedia.org/wiki/Opportunistic_TLS>`__ (STARTTLS) support for
   `IMAP <https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol>`__,
   `SMTP <https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__,
   `POP3 <https://en.wikipedia.org/wiki/Post_Office_Protocol>`__ protocols
