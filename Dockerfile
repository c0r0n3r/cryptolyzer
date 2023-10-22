FROM python:3.8-slim

LABEL maintainer Szilárd Pfeiffer "coroner@pfeifferszilard.hu"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ADD . /usr/src/cryptolyzer

RUN apt-get update && apt-get install --no-install-recommends -y git-core \
 && pip3 install --no-cache-dir /usr/src/cryptolyzer \
 && pip3 install --no-cache-dir --force-reinstall /usr/src/cryptolyzer/submodules/cryptoparser

USER nobody

ENTRYPOINT ["cryptolyze"]
CMD ["--help"]
