FROM python:3.7-alpine3.15

ADD . /tool
RUN apk add --update build-base libffi-dev openssl

WORKDIR /tool
RUN pip install /tool
RUN mkdir /work

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/manifest-tool"]
