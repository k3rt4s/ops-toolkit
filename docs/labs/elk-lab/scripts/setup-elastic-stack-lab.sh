#!/usr/bin/env bash
# Instructions
# - Purpose: Install Elasticsearch and Kibana on an Ubuntu/Debian lab host.
# - Read the root README.md before running this script.
# - Run only in an isolated lab/class environment, not production.
# - Pass all options on the command line; the script does not display menus.
# - Status: Lab reference. Keep with docs; not production automation.

set -Eeuo pipefail

ELASTIC_MAJOR_VERSION="9"
NETWORK_HOST="0.0.0.0"
KIBANA_HOST="0.0.0.0"
CLUSTER_NAME="secops-lab"
NODE_NAME="$(hostname -s)"
START_SERVICES="true"

usage() {
  cat <<'USAGE'
Missing required arguments or invalid option.

Usage:
  sudo ./setup-elastic-stack-lab.sh --cluster-name secops-lab --node-name elk01

Options:
  --cluster-name <name>          Elasticsearch cluster name. Default: secops-lab
  --node-name <name>             Elasticsearch node name. Default: short hostname
  --network-host <address>       Elasticsearch network.host. Default: 0.0.0.0
  --kibana-host <address>        Kibana server.host. Default: 0.0.0.0
  --elastic-major-version <num>  Elastic apt repo major version. Default: 9
  --no-start                     Install and configure packages but do not start services.
  -h, --help                     Show this help.

Notes:
  - Supports Debian/Ubuntu apt-based lab hosts.
  - After first start, use Elastic's generated password and enrollment token output or run:
      sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
      sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
USAGE
}

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

if [[ -z "$CLUSTER_NAME" || -z "$NODE_NAME" || -z "$NETWORK_HOST" || -z "$KIBANA_HOST" || -z "$ELASTIC_MAJOR_VERSION" ]]; then
  usage
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script with sudo." >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This lab script supports apt-based Debian/Ubuntu hosts only." >&2
  exit 1
fi

set_yaml_setting() {
  local file="$1"
  local key="$2"
  local value="$3"

  sed -i "/^[[:space:]]*${key}:/d" "$file"
  printf '%s: %s\n' "$key" "$value" >> "$file"
}

install -d -m 0755 /etc/apt/keyrings
apt-get update
apt-get install -y apt-transport-https ca-certificates curl gnupg

curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch |
  gpg --batch --yes --dearmor -o /etc/apt/keyrings/elastic.gpg
chmod 0644 /etc/apt/keyrings/elastic.gpg

cat > "/etc/apt/sources.list.d/elastic-${ELASTIC_MAJOR_VERSION}.x.list" <<EOF
deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/${ELASTIC_MAJOR_VERSION}.x/apt stable main
EOF

apt-get update
apt-get install -y elasticsearch kibana

cp -a /etc/elasticsearch/elasticsearch.yml "/etc/elasticsearch/elasticsearch.yml.bak.$(date +%Y%m%d%H%M%S)"
set_yaml_setting /etc/elasticsearch/elasticsearch.yml "cluster.name" "${CLUSTER_NAME}"
set_yaml_setting /etc/elasticsearch/elasticsearch.yml "node.name" "${NODE_NAME}"
set_yaml_setting /etc/elasticsearch/elasticsearch.yml "network.host" "${NETWORK_HOST}"
set_yaml_setting /etc/elasticsearch/elasticsearch.yml "http.port" "9200"
set_yaml_setting /etc/elasticsearch/elasticsearch.yml "discovery.type" "single-node"

cp -a /etc/kibana/kibana.yml "/etc/kibana/kibana.yml.bak.$(date +%Y%m%d%H%M%S)"
set_yaml_setting /etc/kibana/kibana.yml "server.host" "\"${KIBANA_HOST}\""
set_yaml_setting /etc/kibana/kibana.yml "server.port" "5601"

systemctl daemon-reload
systemctl enable elasticsearch kibana

if [[ "$START_SERVICES" == "true" ]]; then
  systemctl start elasticsearch
  systemctl start kibana
fi

cat <<EOF
Elastic lab host setup complete.

Elasticsearch: https://${NETWORK_HOST}:9200
Kibana:        http://${KIBANA_HOST}:5601

Next steps:
  sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
  sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
  sudo /usr/share/kibana/bin/kibana-setup --enrollment-token <token>
EOF
