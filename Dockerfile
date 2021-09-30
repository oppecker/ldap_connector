# syntax=docker/dockerfile:1

FROM python:3.8-slim-buster

WORKDIR /app

RUN apt-get update && apt-get install -y gcc python-dev libldap2-dev libsasl2-dev libssl-dev

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY run_audit.py .

ENTRYPOINT ["python3"]
CMD ["run_audit.py"]
