Name:           cryptolyzer
Version:        1.6.0
Release:        1%{?dist}
Summary:        Multi-protocol cryptographic configuration analyzer

License:        MPL-2.0
URL:            https://gitlab.com/coroner/cryptolyzer
Source0:        %{name}_%{version}.tar.xz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel
BuildRequires:  python3-asn1crypto
BuildRequires:  python3-attrs
BuildRequires:  python3-beautifulsoup4
BuildRequires:  python3-certvalidator
BuildRequires:  python3-colorama
BuildRequires:  python3-cryptoparser >= 1.6.0
BuildRequires:  python3-dateutil
%if 0%{?suse_version}
BuildRequires:  python3-dnspython
%else
BuildRequires:  python3-dns
%endif
BuildRequires:  python3-oscrypto
BuildRequires:  python3-pycryptodomex
BuildRequires:  python3-requests
BuildRequires:  python3-urllib3

Requires:       python3-cryptolyzer = %{version}

%description
CryptoLyzer analyzes the cryptographic configuration of network services
supporting TLS, SSH, DNS, IKE, and HTTP. It detects cipher suites,
protocol versions, and cryptographic vulnerabilities including FREAK,
Logjam, ROBOT, and SWEET32. It supports JA3, HASSH, and JA4
fingerprinting of TLS and SSH traffic.

%package -n python3-cryptolyzer
Summary:        Multi-protocol cryptographic analyzer library
Requires:       python3-asn1crypto
Requires:       python3-attrs
Requires:       python3-beautifulsoup4
Requires:       python3-certvalidator
Requires:       python3-colorama
Requires:       python3-cryptoparser >= 1.6.0
Requires:       python3-dateutil
%if 0%{?suse_version}
Requires:       python3-dnspython
%else
Requires:       python3-dns
%endif
Requires:       python3-oscrypto
Requires:       python3-pycryptodomex
Requires:       python3-requests
Requires:       python3-urllib3

%description -n python3-cryptolyzer
CryptoLyzer is an analysis-oriented security library for TLS, SSH, DNS,
IKE, and HTTP protocol analysis. It supports JA3, HASSH, and JA4
fingerprinting of TLS and SSH traffic.

Supported protocols: TLS 1.0-1.3, SSL 2.0-3.0, SSH 2.0, IKEv1, IKEv2,
DNS/DNSSEC, HTTP, FTP, LDAP, RDP, POP3, SMTP, IMAP, XMPP, SIEVE.

%prep
%setup -q -T -c -n %{name}-%{version}
tar -xJf %{SOURCE0} --strip-components=1
sed -i "s/, 'setuptools-scm'//" pyproject.toml
sed -i "s/name = 'CryptoLyzer'/name = 'cryptolyzer'/" pyproject.toml

%build
export SETUPTOOLS_SCM_PRETEND_VERSION=%{version}

%install
export SETUPTOOLS_SCM_PRETEND_VERSION=%{version}
%{__python3} -m pip install --no-build-isolation --no-deps --root %{buildroot} --prefix %{_prefix} .

%check

%files -n python3-cryptolyzer
%{python3_sitelib}/cryptolyzer/
%{python3_sitelib}/cryptolyzer-%{version}.dist-info/
%license LICENSE.txt
%exclude %{_bindir}/cryptolyze

%files
%{_bindir}/cryptolyze

%changelog
* Tue Aug 25 2026 Szilárd Pfeiffer <coroner@pfeifferszilard.hu> - 1.6.0-1
- add IKE client simulation checker for the acceptance of a client proposal set (#185)
- add support for ignoring the supported versions extension to the TLS server (#186)
- read the ALPN protocol names from both codepoints during capability generation (#189)
- forge the ephemeral key of a Montgomery curve during elliptic-curve Diffie-Hellman key exchange (#194)
- handle primality and safe primality independently
- offer the standalone post-quantum signature algorithms in the client hello (#190)
- do not offer TLS 1.3 only named groups in earlier protocol versions (#191)
- handle server hello without the supported versions extension (#186)
- handle connection reset while sending the client hello (#187)
- handle the missing authentication algorithm of TLS 1.3 cipher suites (#196)
- handle a named group whose size is unknown (#194)
- handle servers supporting only ShangMi (SM2) cipher suites (#198)
- offer supported groups to anonymous elliptic-curve Diffie-Hellman servers (#197)
- resolve the protocol handler by protocol version instead of by name (#195)
- handle the GREASE extension in the TLS server (#189)
- keep the state of the capability converter instances separated (#189)
- keep the IKEv1 result when the responder picks an unusable Diffie-Hellman group (#199)
- use a fixed-size private exponent during finite-field Diffie-Hellman key exchange

* Fri Jul 31 2026 Szilárd Pfeiffer <coroner@pfeifferszilard.hu> - 1.5.0-1
- add IKE public keys checker for IKEv1 aggressive-mode and IKEv2 EAP-mode servers (#183)
- add IKE public key request checker for enumerating accepted certification authority hashes (#183)
- use a cryptographically secure random generator for IKE probe secrets (#183)

* Fri Jul 17 2026 Szilárd Pfeiffer <coroner@pfeifferszilard.hu> - 1.4.0-1
- add key exchange completion to the SSH server (#184)
- add certificate request support to the TLS server
- add OCSP staple, EC point formats, and fallback SCSV support to the TLS server (#184)
- add IKE extensions checker (#177)
- do not let a handshake without OCSP staple overwrite the certificate status

* Mon Jun 15 2026 Szilárd Pfeiffer <coroner@pfeifferszilard.hu> - 1.3.0-1
- add Debian and RPM packaging (#181)
- add JA4 tag generation and decoding (#178)
- unify the ja3 and hassh commands into the fingerprint command (#178)
- add TLS 1.3 support to the public key analyzer (#171)
- add IKE cipher suite checker (#168)
- report unhandled alert as analysis error instead of stopping the run (#180)
