FROM debian:11

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /usr/src/fwunify
COPY . .

RUN apt update -y && apt install -y --upgrade python3 python3-distutils curl iptables iputils-ping
RUN curl https://bootstrap.pypa.io/get-pip.py >> scripts/get-pip.py
RUN python3 scripts/get-pip.py && python3 -m pip install --upgrade pip pipenv
RUN python3 -m pipenv requirements >> requirements.txt && python3 -m pip install -r requirements.txt

RUN bash scripts/get-rabbitmq.sh

RUN useradd -G sudo -p fwunify fwunify

CMD ["/bin/bash", "-c", "rabbitmq-plugins enable rabbitmq_management; service rabbitmq-server restart; bash scripts/start_microservices.sh; python3 src/api.py" ]
