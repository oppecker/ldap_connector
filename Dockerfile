# syntax=docker/dockerfile:1

FROM python:3.8-slim-buster

WORKDIR /app

ENV FLASK_APP=ldap_connector/app.py
ENV FLASK_RUN_HOST=0.0.0.0

RUN apt-get update && apt-get install -y gcc python-dev libldap2-dev libsasl2-dev libssl-dev

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
EXPOSE 5000

COPY . .

CMD ["flask", "run"]
