#!/usr/bin/env bash
set -euo pipefail

TARGET_URL="${1:-}"
CONFIG_FILE="${2:-config.yaml}"

if [[ -z "${TARGET_URL}" ]]; then
	echo "Usage: $0 <target-url> [config-file]" >&2
	exit 2
fi
for command_name in yq curl; do
	if ! command -v "${command_name}" >/dev/null 2>&1; then
		echo "Error: ${command_name} is required" >&2
		exit 1
	fi
done
if [[ ! -f "${CONFIG_FILE}" ]]; then
	echo "Error: config file ${CONFIG_FILE} not found" >&2
	exit 1
fi

listen_addr="$(yq -r '.listen_addr // ""' "${CONFIG_FILE}")"
proto="$(yq -r '.proto // "http"' "${CONFIG_FILE}")"
pem_path="$(yq -r '.pem_path // ""' "${CONFIG_FILE}")"
username="$(yq -r '.username // ""' "${CONFIG_FILE}")"
password="$(yq -r '.password // ""' "${CONFIG_FILE}")"

if [[ "${listen_addr}" == \[*\]:* ]]; then
	host="${listen_addr%%]*}"
	host="${host#[}"
	port="${listen_addr##*]:}"
else
	host="${listen_addr%:*}"
	port="${listen_addr##*:}"
fi
if [[ -z "${host}" || -z "${port}" || "${port}" == "${listen_addr}" ]]; then
	echo "Error: listen_addr must use host:port format" >&2
	exit 1
fi

case "${host}" in
	0.0.0.0 | "") host="127.0.0.1" ;;
	::) host="::1" ;;
esac
if [[ "${host}" == *:* ]]; then
	proxy_host="[${host}]"
else
	proxy_host="${host}"
fi
if [[ "${proto}" != "http" && "${proto}" != "https" ]]; then
	echo "Error: proto must be http or https" >&2
	exit 1
fi

curl_args=(
	--silent
	--show-error
	--fail-with-body
	--location
	--connect-timeout "${CONNECT_TIMEOUT_SECONDS:-10}"
	--max-time "${MAX_TIME_SECONDS:-60}"
	--noproxy ""
	--proxy "${proto}://${proxy_host}:${port}"
)

if [[ "${proto}" == "https" ]]; then
	if [[ -z "${pem_path}" ]]; then
		echo "Error: pem_path is required for an HTTPS proxy" >&2
		exit 1
	fi
	if [[ "${pem_path}" != /* ]]; then
		pem_path="$(dirname -- "${CONFIG_FILE}")/${pem_path}"
	fi
	curl_args+=(--proxy-cacert "${pem_path}")
fi

AUTH_CONFIG=""
cleanup() {
	if [[ -n "${AUTH_CONFIG}" ]]; then
		rm -f -- "${AUTH_CONFIG}"
	fi
}
trap cleanup EXIT

if [[ -n "${username}" || -n "${password}" ]]; then
	if [[ -z "${username}" || -z "${password}" ]]; then
		echo "Error: username and password must both be configured" >&2
		exit 1
	fi
	escape_curl_config() {
		local value="$1"
		value="${value//\\/\\\\}"
		value="${value//\"/\\\"}"
		value="${value//$'\n'/\\n}"
		value="${value//$'\r'/\\r}"
		printf '%s' "${value}"
	}
	AUTH_CONFIG="$(mktemp)"
	chmod 0600 "${AUTH_CONFIG}"
	printf 'proxy-user = "%s:%s"\n' \
		"$(escape_curl_config "${username}")" \
		"$(escape_curl_config "${password}")" > "${AUTH_CONFIG}"
	curl_args+=(--config "${AUTH_CONFIG}")
fi

echo "Testing ${TARGET_URL} through ${proto}://${proxy_host}:${port}"
curl "${curl_args[@]}" "${TARGET_URL}"
