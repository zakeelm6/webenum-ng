# Image prete a l'emploi : webenum-ng + les scanners qu'il enveloppe.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip \
      nmap nikto whatweb feroxbuster ffuf nuclei sqlmap dalfox dirb \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/webenum-ng
COPY pyproject.toml README.md LICENSE webenum_ng.py webenum-ng.py ./
RUN pip install --no-cache-dir --break-system-packages .

# les rapports/sorties atterrissent ici (monte un volume dessus)
WORKDIR /scan
ENTRYPOINT ["webenum-ng"]
