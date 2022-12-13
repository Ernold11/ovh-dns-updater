FROM debian:bullseye

RUN apt-get update && apt-get install --no-install-recommends supervisor python3 python3-pip -y && rm -rf /var/lib/apt/lists

ENV SLEEP_TIME=300
COPY requirements.txt .
RUN python3 -m pip install -r requirements.txt

RUN mkdir /src/
COPY src/ovh-ip-update.py /src/

RUN mkdir /src/config
COPY supervisord.conf /etc/

VOLUME /src/config

CMD ["/bin/bash", "-c", "exec supervisord"]
