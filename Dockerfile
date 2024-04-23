FROM python:alpine3.10 as builder

# Set tools versions
ENV YQ_VERSION=latest

RUN apk update \
 && apk add --no-cache git unzip groff build-base libffi-dev cmake

# Install required packages
RUN apk update \
 && apk add --no-cache jq curl git openssh gnupg unzip py3-pip

# Install python packages
RUN pip install deepdiff tabulate gitpython

# Install yq
RUN curl -LO "https://github.com/mikefarah/yq/releases/download/$YQ_VERSION/yq_linux_amd64" \
 && chmod u+x yq_linux_amd64  \
 && mv yq_linux_amd64 /usr/local/bin/yq \
