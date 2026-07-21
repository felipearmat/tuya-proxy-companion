FROM alpine:3.19

RUN apk add --no-cache python3 py3-pip iptables openssl \
    && pip3 install --no-cache-dir --break-system-packages aiohttp cryptography tinytuya

# NOCACHE_0_2_6 — unique marker, never existed before, guarantees cache miss
RUN echo "build 0.2.6" && ls /dev/null
COPY proxy/ /proxy/
COPY run.sh /run.sh
RUN chmod +x /run.sh && \
    grep -q 'ArpSpoofManager' /proxy/main.py && echo "import OK" || \
    { echo "PATCHING: import missing from main.py" && \
      sed -i 's/^from .iptables_manager/from .arp_spoof import ArpSpoofManager\nfrom .iptables_manager/' /proxy/main.py; }

CMD ["/run.sh"]
