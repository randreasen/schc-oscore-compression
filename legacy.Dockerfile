# syntax=docker/dockerfile:1

# FROM python:3.8-slim-buster
FROM python:3.5-slim-buster

# WORKDIR /app
WORKDIR /Users/ricardo/Documents/tesis/aiocoap-schc/myaiocoap

RUN apt-get update
RUN apt-get install --yes build-essential
RUN apt-get install --yes libffi-dev
RUN apt-get install --yes less

COPY  requirements.txt .
RUN pip install --upgrade pip
# RUN pip install -r requirements.txt
RUN pip install cbor
RUN pip install cffi
RUN pip install cryptography
RUN pip install hkdf
RUN pip install ipython ipdb
RUN pip install pytest


# COPY . .
