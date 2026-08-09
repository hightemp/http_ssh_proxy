#!/usr/bin/env bash
set -euo pipefail

KEY_PATH="${1:-server.key}"
CERT_PATH="${2:-server.pem}"

umask 077

openssl req \
	-x509 \
	-nodes \
	-days 365 \
	-newkey rsa:3072 \
	-keyout "${KEY_PATH}" \
	-out "${CERT_PATH}" \
	-subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
	-addext "basicConstraints=critical,CA:FALSE" \
	-addext "keyUsage=critical,digitalSignature,keyEncipherment" \
	-addext "extendedKeyUsage=serverAuth"

chmod 0600 "${KEY_PATH}"
chmod 0644 "${CERT_PATH}"

echo "Generated TLS key: ${KEY_PATH}"
echo "Generated TLS certificate: ${CERT_PATH}"
