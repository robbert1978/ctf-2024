FROM ubuntu:24.04

ENV user parpix
ENV binary parpix
ENV port 12345

RUN apt-get update && \
    apt-get install -y socat python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


RUN useradd -m $user
RUN mkdir -p /app /app/stash && \
    chown $user:$user /app /app/stash

COPY --chown=root:$user helper.py /app/
COPY --chown=root:$user $binary /app/
COPY --chown=root:$user flag /app/

RUN chmod 750 /app/helper.py /app/$binary && \
    chmod 440 /app/flag
RUN chmod u+s /app/helper.py

WORKDIR /app
USER $user
CMD socat TCP4-LISTEN:$port,reuseaddr,fork EXEC:/app/helper.py
EXPOSE $port
