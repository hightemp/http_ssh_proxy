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
RUN_USER="${SUDO_USER:-$(id -un)}"
RUN_GROUP="$(id -gn "${RUN_USER}")"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf -- "${BUILD_DIR}"' EXIT

if [[ ! -f "${UNIT_TEMPLATE}" ]]; then
	echo "Error: ${UNIT_TEMPLATE} not found" >&2
	exit 1
fi
if ! sudo test -f "${CONFIG_FILE}" && [[ ! -f "${SOURCE_CONFIG}" ]]; then
	echo "Error: neither ${CONFIG_FILE} nor ${SOURCE_CONFIG} exists" >&2
	exit 1
fi

echo "Building ${SERVICE_NAME} with version metadata..."
(
	cd "${SCRIPT_DIR}"
	make BINARY_NAME="${BUILD_DIR}/${SERVICE_NAME}" build
)
"${BUILD_DIR}/${SERVICE_NAME}" -version

sudo install -d -m 0755 "${CONFIG_DIR}"
if sudo test -f "${CONFIG_FILE}"; then
	echo "Keeping existing configuration: ${CONFIG_FILE}"
else
	sudo install -m 0600 -o "${RUN_USER}" -g "${RUN_GROUP}" "${SOURCE_CONFIG}" "${CONFIG_FILE}"
	echo "Installed configuration: ${CONFIG_FILE}"
fi
sudo chown "${RUN_USER}:${RUN_GROUP}" "${CONFIG_FILE}"
sudo chmod 0600 "${CONFIG_FILE}"

echo "Validating configuration as ${RUN_USER}..."
(
	cd "${CONFIG_DIR}"
	sudo -H -u "${RUN_USER}" "${BUILD_DIR}/${SERVICE_NAME}" -config "${CONFIG_FILE}" -check-config
)

had_previous=0
if sudo test -x "${BINARY_PATH}"; then
	sudo install -m 0755 "${BINARY_PATH}" "${BACKUP_BINARY_PATH}"
	had_previous=1
	echo "Saved previous binary: ${BACKUP_BINARY_PATH}"
fi
sudo install -m 0755 "${BUILD_DIR}/${SERVICE_NAME}" "${BINARY_PATH}"

sed \
	-e "s/@USER@/${RUN_USER}/g" \
	-e "s/@GROUP@/${RUN_GROUP}/g" \
	"${UNIT_TEMPLATE}" > "${BUILD_DIR}/${SERVICE_NAME}.service"
sudo install -m 0644 "${BUILD_DIR}/${SERVICE_NAME}.service" "${SERVICE_FILE}"

sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}"
sudo systemctl restart "${SERVICE_NAME}"

service_ready=1
for _ in 1 2 3 4 5; do
	sleep 1
	if ! sudo systemctl is-active --quiet "${SERVICE_NAME}"; then
		service_ready=0
		break
	fi
done

if [[ "${service_ready}" != "1" ]]; then
	echo "Error: ${SERVICE_NAME} failed to become active" >&2
	sudo journalctl -u "${SERVICE_NAME}" -n 50 --no-pager >&2 || true
	if [[ "${had_previous}" == "1" ]]; then
		echo "Restoring previous binary..." >&2
		sudo install -m 0755 "${BACKUP_BINARY_PATH}" "${BINARY_PATH}"
		sudo systemctl restart "${SERVICE_NAME}" || true
	else
		echo "No previous binary is available for rollback" >&2
	fi
	exit 1
fi

echo "Service ${SERVICE_NAME} installed and running."
sudo systemctl status "${SERVICE_NAME}" --no-pager -l
