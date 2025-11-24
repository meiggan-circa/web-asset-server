FROM ubuntu:24.04

LABEL maintainer="Specify Collections Consortium <github.com/specify>"

RUN apt-get update && apt-get -y install --no-install-recommends \
        ghostscript \
        imagemagick \
        python3.12 \
        python3.12-venv \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 999 specify && \
        useradd -r -u 999 -g specify specify

RUN mkdir -p /home/specify && chown specify.specify /home/specify

USER specify
WORKDIR /home/specify

COPY --chown=specify:specify requirements.txt .

RUN python3.12 -m venv ve && ve/bin/pip install --no-cache-dir -r requirements.txt

COPY --chown=specify:specify *.py views ./
COPY --chown=specify:specify assets ./assets/

RUN mkdir -p /home/specify/attachments/

CMD ["ve/bin/python", "server.py"]
