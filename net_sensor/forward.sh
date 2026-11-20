#!/bin/sh
# Run the sensor and POST each JSON event line to the backend's /ingest.
# Live capture on $IFACE by default; set PCAP=/path/file.pcap to replay a capture instead.
set -eu
: "${INGEST_URL:=http://127.0.0.1:8080/ingest}"
: "${INDICATORS:=/config/indicators.yaml}"

# Default interface: the one holding the default route (eth0, ens5, enp0s3, ...).
: "${IFACE:=$(awk '$2 == "00000000" { print $1; exit }' /proc/net/route)}"
if [ -n "${PCAP:-}" ]; then src="-r $PCAP"; else src="-i ${IFACE:-eth0}"; fi

# shortcut: one HTTP request per event, fine for one site's traffic; batch lines if ingest becomes the bottleneck.
# shellcheck disable=SC2086
net_sensor -j -c "$INDICATORS" $src "$@" | while IFS= read -r line; do
  curl -fsS -m 5 -o /dev/null -H 'content-type: application/x-ndjson' --data-binary "$line" "$INGEST_URL" \
    || echo "[forward] ingest failed, event dropped" >&2
done
