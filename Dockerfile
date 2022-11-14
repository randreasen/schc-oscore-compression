# syntax=docker/dockerfile:1

FROM python:3.8-slim-buster

WORKDIR /app

COPY requirements.txt .
COPY dev_requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install -r dev_requirements.txt

ENTRYPOINT ["./entrypoint.sh"]
