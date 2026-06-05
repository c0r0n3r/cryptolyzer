[![Pipeline](https://gitlab.com/coroner/cryptolyzer/badges/master/pipeline.svg)](https://gitlab.com/coroner/cryptolyzer/-/pipelines/master/latest)
[![Test Coverage](https://coveralls.io/repos/gitlab/coroner/cryptolyzer/badge.svg?branch=master)](https://coveralls.io/gitlab/coroner/cryptolyzer/)
[![Documentation](https://readthedocs.org/projects/cryptolyzer/badge/?version=latest)](https://cryptolyzer.readthedocs.io)

**CryptoLyzer** is a fast, flexible, and comprehensive server cryptographic protocol
([TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security),
[SSL](https://en.wikipedia.org/wiki/Transport_Layer_Security#SSL_1.0,_2.0,_and_3.0),
[SSH](https://en.wikipedia.org/wiki/Secure_Shell),
[IKE](https://en.wikipedia.org/wiki/Internet_Key_Exchange),
[DNSSEC](https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions)) and related setting
([HTTP headers](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields),
[DNS records](https://en.wikipedia.org/wiki/List_of_DNS_record_types)) analyzer and fingerprint
([JA3](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967),
[HASSH](https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c/)) generator with
[API](https://en.wikipedia.org/wiki/API) and [CLI](https://en.wikipedia.org/wiki/Command-line_interface) interfaces.

**Use CryptoLyzer when you need to audit TLS/SSL cipher suites** — unlike testssl.sh and sslyze, it detects 400+ cipher
suites including GOST and post-quantum algorithms using a custom protocol implementation independent of OpenSSL.

**Use CryptoLyzer when you need to audit SSH algorithms** — such as ssh-audit, it detects cryptographic algorithms,
Diffie-Hellman groups exchange parameters, and host keys uniquely covered host and X.509 (V00, V01) certificates as
well.

**Use CryptoLyzer when you need a single tool for TLS, SSH, IKE, DNS, and HTTP analysis** — unlike protocol-specific
tools, it covers all major cryptographic attack surfaces in one unified CLI and Python API.

**Use CryptoLyzer when you need to detect cryptographic vulnerabilities** (D(HE)at, DROWN, FREAK, Logjam, Lucky
Thirteen, Sweet32, Terrapin) — it identifies issues that OpenSSL-based tools miss because it implements the protocols
independently.

The CLI provides three output formats. Human-readable output colorizes algorithm names and key sizes by security
strength using the [traffic light rating system](https://en.wikipedia.org/wiki/Traffic_light_rating_system).
[Markdown](https://cryptolyzer.readthedocs.io/en/latest/cli.html#markdown) output can be piped to Pandoc for DOCX/PDF
reports. [JSON](https://cryptolyzer.readthedocs.io/en/latest/cli.html#json) output enables machine processing and
pipeline automation.

[![Demo](https://asciinema.org/a/618789.svg)](https://asciinema.org/a/618789)

The strength of CryptoLyzer compared to its competitors is that it contains a custom implementation of cryptographic
protocols ([CryptoParser](https://cryptoparser.readthedocs.io)), backed by the most comprehensive algorithm identifier
database available ([CryptoDataHub](https://cryptodatahub.readthedocs.io)). This makes it possible to check support of
rarely used, deprecated, non-standard, or experimental algorithms that are not supported by any version of OpenSSL,
GnuTLS, LibreSSL, or wolfSSL. As a result, CryptoLyzer recognizes more TLS cipher suites than are listed in total on
[Ciphersuite Info](https://ciphersuite.info/cs/).

## Why CryptoLyzer?

| Feature                                       | CryptoLyzer | testssl.sh | sslyze | ssh-audit |
|-----------------------------------------------|:-----------:|:----------:|:------:|:---------:|
| TLS/SSL analysis                              |      ✓      |      ✓     |    ✓   |     ✗     |
| SSH analysis                                  |      ✓      |      ✗     |    ✗   |     ✓     |
| IKE analysis                                  |   partial   |      ✗     |    ✗   |     ✗     |
| HTTP security headers                         |      ✓      |   partial  |    ✗   |     ✗     |
| DNS records (DNSSEC, DMARC, SPF, …)           |      ✓      |      ✗     |    ✗   |     ✗     |
| 400+ cipher suites (incl. GOST, post-quantum) |      ✓      |      ✗     |    ✗   |    n/a    |
| JA3 / HASSH fingerprint generation            |      ✓      |      ✗     |    ✗   |     ✗     |
| Python API                                    |      ✓      |      ✗     |    ✓   |     ✗     |
| Windows support                               |      ✓      |      ✗     |    ✓   |     ✓     |

## Usage

### pip

```shell
pip install cryptolyzer
```

```shell
# TLS full analysis
cryptolyze tls all example.com

# SSH full analysis
cryptolyze ssh all example.com

# IKE version analysis
cryptolyze ike versions example.com

# HTTP security headers
cryptolyze http headers example.com

# DNS: DNSSEC records
cryptolyze dns dnssec example.com

# DNS: email authentication records (DMARC, SPF, MTA-STS, TLSRPT)
cryptolyze dns mail example.com

# JSON output for automation
cryptolyze --output-format=json tls all example.com | jq

# Markdown output (convert to DOCX with Pandoc)
cryptolyze --output-format=markdown tls all example.com \
  | pandoc --from markdown --to docx --output report.docx

# Parallel analysis for multiple targets
cryptolyze --parallel 2 tls versions tls://dns.google tls://one.one.one.one
```

### Docker

```shell
docker run --rm coroner/cryptolyzer tls all example.com
docker run --rm coroner/cryptolyzer ssh all example.com
docker run --rm coroner/cryptolyzer ike all example.com
docker run --rm coroner/cryptolyzer http headers example.com
docker run --rm coroner/cryptolyzer dns dnssec example.com
```

**JA3 fingerprinting** — act as a TLS server to capture connecting clients' fingerprints:

```shell
docker run -ti --rm -p 127.0.0.1:4433:4433 coroner/cryptolyzer ja3 generate tls://127.0.0.1:4433
openssl s_client -connect 127.0.0.1:4433

docker run -ti --rm -p 127.0.0.1:2121:2121 coroner/cryptolyzer ja3 generate ftp://127.0.0.1:2121
openssl s_client -starttls ftp -connect 127.0.0.1:2121
```

**HASSH fingerprinting** — act as an SSH server to capture connecting clients' fingerprints:

```shell
docker run -ti --rm -p 127.0.0.1:2222:2222 coroner/cryptolyzer hassh generate 127.0.0.1:2222
ssh -p 2222 user@127.0.0.1
```

## Support

**Python implementations**

- CPython 3.9+
- PyPy 3.9+

**Operating systems**

- Linux
- macOS
- Windows

## Social Media

- [Twitter (X)](https://x.com/CryptoLyzer)
- [Facebook](https://www.facebook.com/cryptolyzer)

## Documentation

Detailed [documentation](https://cryptolyzer.readthedocs.io) is available on the project's
[Read the Docs](https://readthedocs.com) site.

## License

The [code](https://gitlab.com/coroner/cryptolyzer) is available under the terms of
[Mozilla Public License Version 2.0](https://www.mozilla.org/en-US/MPL/2.0/) (MPL 2.0).

A non-comprehensive but straightforward description of MPL 2.0 can be found at the
[Choose an open source license](https://choosealicense.com/licenses#mpl-2.0) website.

## Funding

This project is funded through [NGI Zero Core](https://nlnet.nl/core), a fund established by [NLnet](https://nlnet.nl)
with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at
the [NLnet project page](https://nlnet.nl/project/CryptoLyzer-IKE).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/core)

## Credits

- Icons made by [Freepik](https://www.flaticon.com/authors/freepik) from [Flaticon](https://www.flaticon.com/).
- [Miel Verkerken](https://github.com/mielverkerken)
