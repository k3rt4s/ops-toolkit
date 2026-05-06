#!/usr/bin/env bash
# Instructions
# - Purpose: Install Elasticsearch and Kibana on an Ubuntu/Debian lab host.
# - Read the root README.md before running this script.
# - Run only in an isolated lab/class environment, not production.
# - Pass all options on the command line; the script does not display menus.
# - Run with --dry-run first to review the install/configuration plan.
# - Status: Lab reference. Keep with docs; not production automation.

set -Eeuo pipefail

ELASTIC_MAJOR_VERSION="9"
NETWORK_HOST="0.0.0.0"
KIBANA_HOST="0.0.0.0"
CLUSTER_NAME="secops-lab"
NODE_NAME="$(hostname -s)"
START_SERVICES="true"
DRY_RUN="false"
SKIP_APT_UPDATE="false"

usage() {
  cat <<'USAGE'
Missing required arguments or invalid option.

Usage:
  sudo ./setup-elastic-stack-lab.sh --cluster-name secops-lab --node-name elk01 --dry-run
  sudo ./setup-elastic-stack-lab.sh --cluster-name secops-lab --node-name elk01

Options:
  --cluster-name <name>          Elasticsearch cluster name. Default: secops-lab
  --node-name <name>             Elasticsearch node name. Default: short hostname
  --network-host <address>       Elasticsearch network.host. Default: 0.0.0.0
  --kibana-host <address>        Kibana server.host. Default: 0.0.0.0
  --elastic-major-version <num>  Elastic apt repo major version. Default: 9
  --no-start                     Install and configure packages but do not start services.
  --skip-apt-update              Do not run apt update before package installation.
  --dry-run                      Print the plan and commands without changing the host.
  -h, --help                     Show this help.

Notes:
  - Supports Debian/Ubuntu apt-based lab hosts.
  - After first start, use Elastic's generated password and enrollment token output or run:
      sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
      sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
USAGE
}

log() {
  printf '[Elastic lab setup] %s\n' "$*"
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

set_yaml_setting() {
  local file="$1"
  local key="$2"
  local value="$3"

  run_cmd sed -i "/^[[:space:]]*${key}:/d" "$file"
  append_file "$file" "${key}: ${value}"
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
      --cluster-name)
        CLUSTER_NAME="${2:-}"
        shift 2
        ;;
      --node-name)
        NODE_NAME="${2:-}"
        shift 2
        ;;
      --network-host)
        NETWORK_HOST="${2:-}"
        shift 2
        ;;
      --kibana-host)
        KIBANA_HOST="${2:-}"
        shift 2
        ;;
      --elastic-major-version)
        ELASTIC_MAJOR_VERSION="${2:-}"
        shift 2
        ;;
      --no-start)
        START_SERVICES="false"
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
  if [[ -z "$CLUSTER_NAME" || -z "$NODE_NAME" || -z "$NETWORK_HOST" || -z "$KIBANA_HOST" || -z "$ELASTIC_MAJOR_VERSION" ]]; then
    usage
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
Elastic lab setup plan:
  Cluster name:          ${CLUSTER_NAME}
  Node name:             ${NODE_NAME}
  Elasticsearch host:    ${NETWORK_HOST}
  Kibana host:           ${KIBANA_HOST}
  Elastic major version: ${ELASTIC_MAJOR_VERSION}
  Start services:        ${START_SERVICES}
  Run apt update:        $([[ "$SKIP_APT_UPDATE" == "true" ]] && echo "false" || echo "true")
  Dry run:               ${DRY_RUN}
EOF
}

install_elastic_stack() {
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
  run_cmd apt-get install -y elasticsearch kibana

  run_cmd cp -a /etc/elasticsearch/elasticsearch.yml "/etc/elasticsearch/elasticsearch.yml.bak.$(date +%Y%m%d%H%M%S)"
  set_yaml_setting /etc/elasticsearch/elasticsearch.yml "cluster.name" "${CLUSTER_NAME}"
  set_yaml_setting /etc/elasticsearch/elasticsearch.yml "node.name" "${NODE_NAME}"
  set_yaml_setting /etc/elasticsearch/elasticsearch.yml "network.host" "${NETWORK_HOST}"
  set_yaml_setting /etc/elasticsearch/elasticsearch.yml "http.port" "9200"
  set_yaml_setting /etc/elasticsearch/elasticsearch.yml "discovery.type" "single-node"

  run_cmd cp -a /etc/kibana/kibana.yml "/etc/kibana/kibana.yml.bak.$(date +%Y%m%d%H%M%S)"
  set_yaml_setting /etc/kibana/kibana.yml "server.host" "\"${KIBANA_HOST}\""
  set_yaml_setting /etc/kibana/kibana.yml "server.port" "5601"

  run_cmd systemctl daemon-reload
  run_cmd systemctl enable elasticsearch kibana

  if [[ "$START_SERVICES" == "true" ]]; then
    run_cmd systemctl start elasticsearch
    run_cmd systemctl start kibana
  fi
}

main() {
  parse_args "$@"
  validate_args
  print_plan
  install_elastic_stack
  cat <<EOF
Elastic lab host setup complete.

Elasticsearch: https://${NETWORK_HOST}:9200
Kibana:        http://${KIBANA_HOST}:5601

Next steps:
  sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
  sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
  sudo /usr/share/kibana/bin/kibana-setup --enrollment-token <token>
EOF
}

main "$@"
