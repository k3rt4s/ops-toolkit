#!/usr/bin/env bash
# Instructions
# - Purpose: Install and configure Filebeat on an Ubuntu/Debian lab host.
# - Read the root README.md before running this script.
# - Run only in an isolated lab/class environment, not production.
# - Pass all options on the command line; the script does not display menus.
# - Run with --dry-run first to review the install/configuration plan.
# - Status: Lab reference. Keep with docs; not production automation.

set -Eeuo pipefail

ELASTIC_MAJOR_VERSION="9"
ELASTIC_HOST=""
KIBANA_HOST=""
ELASTIC_USERNAME=""
ELASTIC_PASSWORD=""
ELASTIC_CA_CERT=""
ALLOW_INSECURE_LAB="false"
ENABLE_SYSTEM_MODULE="true"
START_SERVICE="true"
DRY_RUN="false"
SKIP_APT_UPDATE="false"

usage() {
  cat <<'USAGE'
Missing required arguments or invalid option.

Usage:
  sudo ./setup-filebeat-lab-agent.sh --elastic-host https://elk01:9200 --kibana-host http://elk01:5601 --elastic-username elastic --elastic-password '<password>' --dry-run
  sudo ./setup-filebeat-lab-agent.sh --elastic-host https://elk01:9200 --kibana-host http://elk01:5601 --elastic-username elastic --elastic-password '<password>' --elastic-ca-cert ./http_ca.crt

Options:
  --elastic-host <url>           Elasticsearch URL, for example https://elk01:9200. Required.
  --kibana-host <url>            Kibana URL, for example http://elk01:5601. Required.
  --elastic-username <name>      Elasticsearch username. Required unless using a preconfigured keystore.
  --elastic-password <value>     Elasticsearch password. Required unless using a preconfigured keystore.
  --elastic-ca-cert <path>       Optional CA certificate path copied from the Elasticsearch host.
  --allow-insecure-lab           Disable Elasticsearch TLS verification. Lab-only fallback.
  --elastic-major-version <num>  Elastic apt repo major version. Default: 9
  --no-system-module             Do not enable the Filebeat system module.
  --no-start                     Install and configure Filebeat but do not start it.
  --skip-apt-update              Do not run apt update before package installation.
  --dry-run                      Print the plan and commands without changing the host.
  -h, --help                     Show this help.
USAGE
}

log() {
  printf '[Filebeat lab setup] %s\n' "$*"
}

run_cmd() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[dry-run] '
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi

  "$@"
}

write_file() {
  local path="$1"
  local content="$2"

  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[dry-run] write %s\n%s\n' "$path" "$content"
    return 0
  fi

  printf '%s\n' "$content" > "$path"
}

append_file() {
  local path="$1"
  local content="$2"

  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[dry-run] append %s\n%s\n' "$path" "$content"
    return 0
  fi

  printf '%s\n' "$content" >> "$path"
}

require_debian_family() {
  if [[ ! -r /etc/os-release ]]; then
    log "Unable to determine OS because /etc/os-release is missing."
    exit 1
  fi

  # shellcheck disable=SC1091
  source /etc/os-release
  local os_id="${ID:-}"
  local os_like="${ID_LIKE:-}"
  if [[ "$os_id" != "debian" && "$os_id" != "ubuntu" && "$os_like" != *"debian"* ]]; then
    log "This lab script supports Debian/Ubuntu apt-based hosts only. Detected ID='${os_id}', ID_LIKE='${os_like}'."
    exit 1
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --elastic-host)
        ELASTIC_HOST="${2:-}"
        shift 2
        ;;
      --kibana-host)
        KIBANA_HOST="${2:-}"
        shift 2
        ;;
      --elastic-username)
        ELASTIC_USERNAME="${2:-}"
        shift 2
        ;;
      --elastic-password)
        ELASTIC_PASSWORD="${2:-}"
        shift 2
        ;;
      --elastic-ca-cert)
        ELASTIC_CA_CERT="${2:-}"
        shift 2
        ;;
      --allow-insecure-lab)
        ALLOW_INSECURE_LAB="true"
        shift
        ;;
      --elastic-major-version)
        ELASTIC_MAJOR_VERSION="${2:-}"
        shift 2
        ;;
      --no-system-module)
        ENABLE_SYSTEM_MODULE="false"
        shift
        ;;
      --no-start)
        START_SERVICE="false"
        shift
        ;;
      --skip-apt-update)
        SKIP_APT_UPDATE="true"
        shift
        ;;
      --dry-run)
        DRY_RUN="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        usage
        exit 2
        ;;
    esac
  done
}

validate_args() {
  if [[ -z "$ELASTIC_HOST" || -z "$KIBANA_HOST" || -z "$ELASTIC_MAJOR_VERSION" ]]; then
    usage
    exit 2
  fi

  if [[ -z "$ELASTIC_USERNAME" || -z "$ELASTIC_PASSWORD" ]]; then
    log "Missing --elastic-username or --elastic-password."
    usage
    exit 2
  fi

  if [[ -n "$ELASTIC_CA_CERT" && ! -f "$ELASTIC_CA_CERT" ]]; then
    log "CA certificate was not found: $ELASTIC_CA_CERT"
    exit 1
  fi

  if [[ "$ELASTIC_HOST" == https://* && -z "$ELASTIC_CA_CERT" && "$ALLOW_INSECURE_LAB" != "true" ]]; then
    log "HTTPS Elasticsearch output requires --elastic-ca-cert or explicit --allow-insecure-lab."
    exit 2
  fi

  if [[ ! "$ELASTIC_MAJOR_VERSION" =~ ^[0-9]+$ ]]; then
    log "--elastic-major-version must be a number."
    exit 2
  fi

  if [[ "${EUID}" -ne 0 && "$DRY_RUN" != "true" ]]; then
    log "Run this script with sudo, or use --dry-run to preview."
    exit 1
  fi

  require_debian_family
  command -v apt-get >/dev/null 2>&1 || { log "apt-get was not found."; exit 1; }
}

print_plan() {
  cat <<EOF
Filebeat lab setup plan:
  Elasticsearch host:    ${ELASTIC_HOST}
  Kibana host:           ${KIBANA_HOST}
  Elastic username:      ${ELASTIC_USERNAME}
  Password provided:     $([[ -n "$ELASTIC_PASSWORD" ]] && echo "true" || echo "false")
  CA certificate:        ${ELASTIC_CA_CERT:-none}
  Allow insecure TLS:    ${ALLOW_INSECURE_LAB}
  Elastic major version: ${ELASTIC_MAJOR_VERSION}
  Enable system module:  ${ENABLE_SYSTEM_MODULE}
  Start service:         ${START_SERVICE}
  Run apt update:        $([[ "$SKIP_APT_UPDATE" == "true" ]] && echo "false" || echo "true")
  Dry run:               ${DRY_RUN}
EOF
}

install_filebeat() {
  run_cmd install -d -m 0755 /etc/apt/keyrings
  if [[ "$SKIP_APT_UPDATE" != "true" ]]; then
    run_cmd apt-get update
  fi
  run_cmd apt-get install -y apt-transport-https ca-certificates curl gnupg

  if [[ "$DRY_RUN" == "true" ]]; then
    log "Would download Elastic GPG key and write /etc/apt/keyrings/elastic.gpg"
  else
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch |
      gpg --batch --yes --dearmor -o /etc/apt/keyrings/elastic.gpg
    chmod 0644 /etc/apt/keyrings/elastic.gpg
  fi

  write_file "/etc/apt/sources.list.d/elastic-${ELASTIC_MAJOR_VERSION}.x.list" \
"deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/${ELASTIC_MAJOR_VERSION}.x/apt stable main"

  if [[ "$SKIP_APT_UPDATE" != "true" ]]; then
    run_cmd apt-get update
  fi
  run_cmd apt-get install -y filebeat
  run_cmd cp -a /etc/filebeat/filebeat.yml "/etc/filebeat/filebeat.yml.bak.$(date +%Y%m%d%H%M%S)"

  write_file /etc/filebeat/filebeat.yml \
"filebeat.inputs:
  - type: filestream
    id: syslog-filestream
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/auth.log

setup.kibana:
  host: \"${KIBANA_HOST}\"

output.elasticsearch:
  hosts: [\"${ELASTIC_HOST}\"]
  username: \"${ELASTIC_USERNAME}\"
  password: \"${ELASTIC_PASSWORD}\""

  if [[ -n "$ELASTIC_CA_CERT" ]]; then
    run_cmd install -d -m 0755 /etc/filebeat/certs
    run_cmd install -m 0644 "$ELASTIC_CA_CERT" /etc/filebeat/certs/elasticsearch-ca.crt
    append_file /etc/filebeat/filebeat.yml '  ssl.certificate_authorities: ["/etc/filebeat/certs/elasticsearch-ca.crt"]'
  elif [[ "$ALLOW_INSECURE_LAB" == "true" ]]; then
    append_file /etc/filebeat/filebeat.yml '  ssl.verification_mode: none'
  fi

  if [[ "$ENABLE_SYSTEM_MODULE" == "true" ]]; then
    run_cmd filebeat modules enable system
  fi

  run_cmd filebeat test config
  run_cmd systemctl enable filebeat

  if [[ "$START_SERVICE" == "true" ]]; then
    run_cmd systemctl restart filebeat
  fi
}

main() {
  parse_args "$@"
  validate_args
  print_plan
  install_filebeat
  cat <<EOF
Filebeat lab agent setup complete.

Elasticsearch output: ${ELASTIC_HOST}
Kibana setup host:     ${KIBANA_HOST}
EOF
}

main "$@"
