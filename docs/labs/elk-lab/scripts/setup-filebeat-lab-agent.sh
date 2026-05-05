#!/usr/bin/env bash
# Instructions
# - Purpose: Install and configure Filebeat on an Ubuntu/Debian lab host.
# - Read the root README.md before running this script.
# - Run only in an isolated lab/class environment, not production.
# - Pass all options on the command line; the script does not display menus.
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

usage() {
  cat <<'USAGE'
Missing required arguments or invalid option.

Usage:
  sudo ./setup-filebeat-lab-agent.sh --elastic-host https://elk01:9200 --kibana-host http://elk01:5601 --elastic-username elastic --elastic-password '<password>'

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
  -h, --help                     Show this help.
USAGE
}

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

if [[ -z "$ELASTIC_HOST" || -z "$KIBANA_HOST" || -z "$ELASTIC_MAJOR_VERSION" ]]; then
  usage
  exit 2
fi

if [[ -z "$ELASTIC_USERNAME" || -z "$ELASTIC_PASSWORD" ]]; then
  echo "Missing --elastic-username or --elastic-password." >&2
  usage
  exit 2
fi

if [[ -n "$ELASTIC_CA_CERT" && ! -f "$ELASTIC_CA_CERT" ]]; then
  echo "CA certificate was not found: $ELASTIC_CA_CERT" >&2
  exit 1
fi

if [[ "$ELASTIC_HOST" == https://* && -z "$ELASTIC_CA_CERT" && "$ALLOW_INSECURE_LAB" != "true" ]]; then
  echo "HTTPS Elasticsearch output requires --elastic-ca-cert or explicit --allow-insecure-lab." >&2
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
apt-get install -y filebeat

cp -a /etc/filebeat/filebeat.yml "/etc/filebeat/filebeat.yml.bak.$(date +%Y%m%d%H%M%S)"

cat > /etc/filebeat/filebeat.yml <<EOF
filebeat.inputs:
  - type: filestream
    id: syslog-filestream
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/auth.log

setup.kibana:
  host: "${KIBANA_HOST}"

output.elasticsearch:
  hosts: ["${ELASTIC_HOST}"]
  username: "${ELASTIC_USERNAME}"
  password: "${ELASTIC_PASSWORD}"
EOF

if [[ -n "$ELASTIC_CA_CERT" ]]; then
  install -d -m 0755 /etc/filebeat/certs
  install -m 0644 "$ELASTIC_CA_CERT" /etc/filebeat/certs/elasticsearch-ca.crt
  cat >> /etc/filebeat/filebeat.yml <<'EOF'
  ssl.certificate_authorities: ["/etc/filebeat/certs/elasticsearch-ca.crt"]
EOF
elif [[ "$ALLOW_INSECURE_LAB" == "true" ]]; then
  cat >> /etc/filebeat/filebeat.yml <<'EOF'
  ssl.verification_mode: none
EOF
fi

if [[ "$ENABLE_SYSTEM_MODULE" == "true" ]]; then
  filebeat modules enable system
fi

filebeat test config
systemctl enable filebeat

if [[ "$START_SERVICE" == "true" ]]; then
  systemctl restart filebeat
fi

cat <<EOF
Filebeat lab agent setup complete.

Elasticsearch output: ${ELASTIC_HOST}
Kibana setup host:     ${KIBANA_HOST}
EOF
