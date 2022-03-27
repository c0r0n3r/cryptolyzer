# Summary

**CryptoLyzer** is a fast and flexible server cryptographic settings analyzer library for Python with an easy-to-use
[command line interface](https://en.wikipedia.org/wiki/Command-line_interface) with both human-readable ([Markdown](
https://en.wikipedia.org/wiki/Markdown)) and machine-readable ([JSON](https://en.wikipedia.org/wiki/JSON)) output.
It works with multiple cryptographic protocols ([SSL](
https://en.wikipedia.org/wiki/Transport_Layer_Security#SSL_1.0,_2.0,_and_3.0)/
[TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security), [opportunistic TLS](
https://en.wikipedia.org/wiki/Opportunistic_TLS), [SSH](https://en.wikipedia.org/wiki/Secure_Shell)) and analyzes
additional security mechanisms ([web security](https://infosec.mozilla.org/guidelines/web_security) related 
[HTTP response header fields](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#Response_fields), 
[JA3 tag](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)).

## What is it and what is it not?

The main purpose of creating this application is the fact, that cryptography protocol analysis differs in many aspect
from establishing a connection using a cryptographic protocol. Analysis is mostly testing where we trigger special and
corner cases of the protocol and we also trying to establish connection with hardly supported, experimental, obsoleted
or even deprecated mechanisms or algorithms which are may or may not supported by the latest or any version of an
implementation of the cryptographic protocol.

As follows, it is neither a comprehensive nor a secure client/server implementation of any cryptographic protocol. On
the one hand analyzer implements only the absolutely necessary parts of the protocol to interact with servers. On the
other it may use completely insecure algorithms and mechanisms. It is not designed and contraindicated to use these
client/server implementations establishing secure connections. If you are searching for proper cryptographic protocol
implementations, there are several existing wrappers and native implementations for Python (eg: M2Crypto, pyOpenSSL,
Paramiko, \...).

# Quick start

CryptoLyzer can be installed directly via pip

```shell
pip install cryptolyzer

cryptolyze tls all www.example.com
cryptolyze tls1_2 ciphers www.example.com
cryptolyze ssh2 ciphers www.example.com
cryptolyze http headers www.example.com
```

or can be used via Docker

```shell
docker run --rm coroner/cryptolyzer tls all www.example.com
docker run --rm coroner/cryptolyzer tls1_2 ciphers www.example.com
docker run --rm coroner/cryptolyzer ssh2 ciphers www.example.com
docker run --rm coroner/cryptolyzer http headers www.example.com
```

```shell
docker run -ti --rm -p 127.0.0.1:4433:4433 coroner/cryptolyzer ja3 generate 0.0.0.0:4433
openssl s_client -connect 127.0.0.1:4433

docker run -ti --rm -p 127.0.0.1:2121:2121 coroner/cryptolyzer ja3 generate ftp://0.0.0.0:2121
openssl s_client -starttls ftp -connect 127.0.0.1:2121
```

or via APT on Debian based systems

```shell
apt update && apt install -y gnupg2 curl
echo 'deb https://download.opensuse.org/repositories/home:/pfeiffersz:/cryptolyzer:/dev/Debian_10/ /' >/etc/apt/sources.list.d/cryptolyzer.list
curl -s https://download.opensuse.org/repositories/home:/pfeiffersz:/cryptolyzer:/dev/Debian_10/Release.key | apt-key add -

apt update && apt install -y python3-pkg-resources python3-cryptoparser python3-cryptolyzer

cryptolyze tls all www.example.com
cryptolyze tls1_2 ciphers www.example.com
cryptolyze ssh2 ciphers www.example.com
cryptolyze http headers www.example.com
```

or via DNF on Fedora based systems

```shell
dnf install 'dnf-command(config-manager)'
dnf config-manager --add-repo https://download.opensuse.org/repositories/home:/pfeiffersz:/cryptolyzer:/dev/Fedora_31/
rpm --import http://download.opensuse.org/repositories/home:/pfeiffersz:/cryptolyzer:/dev/Fedora_31/repodata/repomd.xml.key
dnf install python3-urllib3 python3-cryptography cryptoparser cryptolyzer
```

### Development environment

If you want to setup a development environment, you are in need of [pipenv](https://docs.pipenv.org/).

```shell
git clone https://gitlab.com/coroner/cryptolyzer
cd cryptolyzer
pipenv install --dev
pipenv run python setup.py develop
pipenv shell
cryptolyze -h
```

# Features

## SSH

### Differentiators

* checks supported Diffie-Hellman (group exchange) key sizes
* analyzes server protocol version string to identify application server vendor and version

### Protocols

* [SSH 2.0](https://tools.ietf.org/html/rfc4253)

### Analyzers

Supported analyzers by cryptographic protocol versions

| Analyzers                                | SSH<br>2.0 |
| ---------------------------------------- | ---------- |
| Cipher Suites (`ciphers`)                | ✓          |
| Diffie-Hellman parameters (`dhparams`)   | ✓          |
| Host Keys (`pubkeys`)                    | ✓          |

## SSL/TLS

### Differentiators

* checks 10+ application layer protocols with [opportunistic TLS](https://en.wikipedia.org/wiki/Opportunistic_TLS)
  capability
* checks TLS 1.3 draft versions, not just finnal version
* checks each cipher suites discussed on [ciphersuite.info](https://ciphersuite.info), not just supported by 
  [GnuTls](https://www.gnutls.org/), [LibreSSL](https://www.libressl.org/), [OpenSSL](https://www.openssl.org/), or
  [wolfSSL](https://www.wolfssl.com/)
* checks [GOST](https://en.wikipedia.org/wiki/GOST) (national standards of the Russian Federation and CIS countries)
  cipher suites
* checks whether Diffie-Hellman
  * public parameter is a [safe prime](https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes)
  * key is [reused](https://security.stackexchange.com/questions/225209/what-is-ecdh-public-server-param-reuse)

### Analyzers

Supported analyzers by cryptographic protocol versions

| Analyzers                                |SSL<br>2.0|SSL<br>3.0|TLS<br>1.0|TLS<br>1.1|TLS<br>1.2|TLS<br>1.3|
| ---------------------------------------- | ----- | ----- | ----- | ----- | ----- | ----- |
| Cipher Suites (``ciphers``)              |   ✓   |   ✓   |   ✓   |   ✓   |   ✓   |   ✓   |
| X.509 Public Keys (``pubkeys``)          |   ✓   |   ✓   |   ✓   |   ✓   |   ✓   |   ✗   |
| X.509 Public Key Request (``pubkeyreq``) |  n/a  |   ✓   |   ✓   |   ✓   |   ✓   |   ✗   |
| Elliptic Curves (``curves``)             |  n/a  |  n/a  |   ✓   |   ✓   |   ✓   |   ✓   |
| Diffie-Hellman parameters (``dhparams``) |  n/a  |  n/a  |   ✓   |   ✓   |   ✓   |   ✓   |
| Extensions (``extensions``)              |  n/a  |  n/a  |  n/a  |  n/a  |   ✓   |   ✓   |
| Signature Algorithms (``sigalgos``)      |  n/a  |  n/a  |  n/a  |   ✓   |   ✓   |   ✓   |


### Protocols

#### Transport Layer

* Secure Socket Layer (SSL)
  * [SSL 2.0](https://tools.ietf.org/html/draft-hickman-netscape-ssl-00)
  * [SSL 3.0](https://tools.ietf.org/html/rfc6101)
* Transport Layer Security (TLS)
  * [TLS 1.0](https://tools.ietf.org/html/rfc2246)
  * [TLS 1.1](https://tools.ietf.org/html/rfc4346)
  * [TLS 1.2](https://tools.ietf.org/html/rfc5246)
  * [TLS 1.3](https://tools.ietf.org/html/rfc8446)

#### Application Layer

[Opportunistic TLS](https://en.wikipedia.org/wiki/Opportunistic_TLS) or STARTTLS) is an extension of an application
layer protocol, whichs offer a way to upgrade a plain text connection to an encrypted ione without using a separate
port.

* [FTP](https://en.wikipedia.org/wiki/File_Transfer_Protocol)
* [IMAP](https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol)
* [LDAP](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
* [LMTP](https://en.wikipedia.org/wiki/Local_Mail_Transfer_Protocol)
* [NNTP](https://en.wikipedia.org/wiki/Network_News_Transfer_Protocol)
* [POP3](https://en.wikipedia.org/wiki/Post_Office_Protocol)
* [PostgreSQL](https://en.wikipedia.org/wiki/PostgreSQL)
* [RDP](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)
* [Sieve](https://en.wikipedia.org/wiki/Sieve_(mail_filtering_language))
* [SMTP](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)
* [XMPP (Jabber)](https://en.wikipedia.org/wiki/XMPP)

### Extensions

* [application-layer protocol negotiation](https://www.rfc-editor.org/rfc/rfc5077.html)
* [encrypt-then-MAC](https://www.rfc-editor.org/rfc/rfc7366.html)
* [extended master secret](https://www.rfc-editor.org/rfc/rfc7627.html)
* [next protocols negotiation](https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html)
* [renegotiation indication](https://www.rfc-editor.org/rfc/rfc5746.html)
* [session ticket](https://www.rfc-editor.org/rfc/rfc5077.html)

## Fingerprinting

1.  generates [JA3 tag](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967) of any
    connecting TLS client independently from its type (graphical/cli, browser/email client/\...)
  * [FTP](https://en.wikipedia.org/wiki/File_Transfer_Protocol)
  * [LDAP](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
  * [LMTP](https://en.wikipedia.org/wiki/Local_Mail_Transfer_Protocol)
  * [NNTP](https://en.wikipedia.org/wiki/Network_News_Transfer_Protocol)
  * [POP3](https://en.wikipedia.org/wiki/Post_Office_Protocol)
  * [PostgreSQL](https://en.wikipedia.org/wiki/PostgreSQL)
  * [RDP](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol)
  * [Sieve](https://en.wikipedia.org/wiki/Sieve_(mail_filtering_language))
  * [SMTP](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)
2.  decodes existing [JA3 tags](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967) by
    showing human-readable format of the TLS parameters represented by the tag

## Hypertext Transfer Protocol (HTTP)

### Analyzers

#### Headers (`headers`)

* generic headers
  * [Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type)
  * [Server](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server)
* caching headers
  * [Age](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Age)
  * [Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)
  * [Date](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date)
  * [ETag](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag)
  * [Expires](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires)
  * [Last-Modified](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified)
  * [Pragma](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma)
* security headers
  * [Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT)
  * [Expect-Staple](https://scotthelme.co.uk/designing-a-new-security-header-expect-staple)
  * [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
  * [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
  * [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
  * [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)

# Support

## Python implementation

* CPython (2.7, \>=3.3)
* PyPy (2.7, 3.5)

## Operating systems

* Linux
* macOS
* Windows

## Social Media

* [Twitter](https://twitter.com/CryptoLyzer)
* [Facebook](https://www.facebook.com/cryptolyzer)

## Credits

Icons made by [Freepik](https://www.flaticon.com/authors/freepik) from [Flaticon](https://www.flaticon.com/).

## License

The code is available under the terms of Mozilla Public License Version 2.0 (MPL 2.0).

A non-comprehensive, but straightforward description of MPL 2 can be found at [Choose an open source
license](https://choosealicense.com/licenses#mpl-2.0) website.
