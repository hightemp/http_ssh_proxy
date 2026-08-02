#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="http_ssh_proxy"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CONFIG_DIR="/etc/${SERVICE_NAME}"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
BINARY_PATH="/usr/local/bin/${SERVICE_NAME}"
BACKUP_BINARY_PATH="${BINARY_PATH}.previous"
SOURCE_CONFIG="${SCRIPT_DIR}/config.yaml"
UNIT_TEMPLATE="${SCRIPT_DIR}/${SERVICE_NAME}.service"
RUN_USER="${SUDO_USER:-${USER}}"
RUN_GROUP="$(id -gn "${RUN_USER}")"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf -- "${BUILD_DIR}"' EXIT

if [[ ! -f "${SOURCE_CONFIG}" ]]; then
	echo "Error: ${SOURCE_CONFIG} not found" >&2
	exit 1
fi
if [[ ! -f "${UNIT_TEMPLATE}" ]]; then
	echo "Error: ${UNIT_TEMPLATE} not found" >&2
	exit 1
fi

echo "Building ${SERVICE_NAME}..."
(
	cd "${SCRIPT_DIR}"
	go build -trimpath -o "${BUILD_DIR}/${SERVICE_NAME}" .
)

sudo install -d -m 0755 "${CONFIG_DIR}"
if sudo test -x "${BINARY_PATH}"; then
	sudo install -m 0755 "${BINARY_PATH}" "${BACKUP_BINARY_PATH}"
	echo "Saved previous binary: ${BACKUP_BINARY_PATH}"
fi
sudo install -m 0755 "${BUILD_DIR}/${SERVICE_NAME}" "${BINARY_PATH}"

if sudo test -f "${CONFIG_FILE}"; then
	echo "Keeping existing configuration: ${CONFIG_FILE}"
else
	sudo install -m 0600 -o "${RUN_USER}" -g "${RUN_GROUP}" "${SOURCE_CONFIG}" "${CONFIG_FILE}"
	echo "Installed configuration: ${CONFIG_FILE}"
fi

sed \
	-e "s/@USER@/${RUN_USER}/g" \
	-e "s/@GROUP@/${RUN_GROUP}/g" \
	"${UNIT_TEMPLATE}" > "${BUILD_DIR}/${SERVICE_NAME}.service"
sudo install -m 0644 "${BUILD_DIR}/${SERVICE_NAME}.service" "${SERVICE_FILE}"

sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}"
sudo systemctl restart "${SERVICE_NAME}"

echo "Service ${SERVICE_NAME} installed and restarted."
sudo systemctl status "${SERVICE_NAME}" --no-pager -l
