FROM python:3.8-slim

LABEL maintainer Szilárd Pfeiffer "coroner@pfeifferszilard.hu"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ADD . /usr/src/cryptolyzer

RUN pip3 --no-cache-dir install /usr/src/cryptolyzer \
 && pip3 --no-cache-dir install --force-reinstall /usr/src/cryptolyzer/submodules/cryptoparser 

USER nobody

ENTRYPOINT ["cryptolyze"]
CMD ["--help"]
