FROM alpine:3.19

RUN apk add --no-cache python3 py3-pip iptables openssl wget \
    && pip3 install --no-cache-dir --break-system-packages aiohttp cryptography tinytuya

ARG BUILD_VERSION=0.3.3

# Download source directly from GitHub to bypass stale build context
RUN mkdir -p /proxy && \
    wget -qO /tmp/src.tar.gz https://github.com/felipearmat/tuya-proxy-companion/archive/refs/heads/main.tar.gz && \
    tar -xzf /tmp/src.tar.gz --strip=3 -C /proxy/ \
        tuya-proxy-companion-main/tuya_proxy_companion/proxy/ && \
    rm -f /tmp/src.tar.gz && \
    echo "=== main.py import check ===" && \
    grep 'ArpSpoofManager' /proxy/main.py || echo "WARNING: import missing"

COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
