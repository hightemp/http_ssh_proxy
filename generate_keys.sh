#!/usr/bin/env bash
set -euo pipefail

KEY_PATH="${1:-server.key}"
CERT_PATH="${2:-server.pem}"
COMMON_NAME="${3:-localhost}"
TLS_DAYS="${TLS_DAYS:-365}"
TLS_SAN="${TLS_SAN:-DNS:localhost,IP:127.0.0.1,IP:::1}"
FORCE="${FORCE:-0}"

if ! command -v openssl >/dev/null 2>&1; then
	echo "Error: openssl is required" >&2
	exit 1
fi
if [[ ! "${TLS_DAYS}" =~ ^[1-9][0-9]*$ ]]; then
	echo "Error: TLS_DAYS must be a positive integer" >&2
	exit 1
fi
if [[ "${KEY_PATH}" == "${CERT_PATH}" ]]; then
	echo "Error: key and certificate paths must be different" >&2
	exit 1
fi
if [[ "${FORCE}" != "1" ]] && { [[ -e "${KEY_PATH}" ]] || [[ -e "${CERT_PATH}" ]]; }; then
	echo "Error: refusing to overwrite an existing key or certificate; set FORCE=1 to replace both" >&2
	exit 1
fi
if [[ ! -d "$(dirname -- "${KEY_PATH}")" ]] || [[ ! -d "$(dirname -- "${CERT_PATH}")" ]]; then
	echo "Error: output directories must already exist" >&2
	exit 1
fi

umask 077
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "${TEMP_DIR}"' EXIT

openssl req \
	-x509 \
	-nodes \
	-days "${TLS_DAYS}" \
	-newkey rsa:3072 \
	-keyout "${TEMP_DIR}/server.key" \
	-out "${TEMP_DIR}/server.pem" \
	-subj "/CN=${COMMON_NAME}" \
	-addext "subjectAltName=${TLS_SAN}" \
	-addext "basicConstraints=critical,CA:FALSE" \
	-addext "keyUsage=critical,digitalSignature,keyEncipherment" \
	-addext "extendedKeyUsage=serverAuth"

install -m 0600 "${TEMP_DIR}/server.key" "${KEY_PATH}"
install -m 0644 "${TEMP_DIR}/server.pem" "${CERT_PATH}"

echo "Generated TLS key: ${KEY_PATH}"
echo "Generated TLS certificate: ${CERT_PATH}"
