FROM alpine:3.19

RUN apk add --no-cache python3 py3-pip iptables openssl \
    && pip3 install --no-cache-dir --break-system-packages aiohttp cryptography

COPY proxy/ /proxy/
COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
