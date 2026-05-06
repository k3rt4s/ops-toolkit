#!/usr/bin/env bash
# Instructions
# - Purpose: Install DVWA on an Ubuntu/Debian lab target host.
# - Read the root README.md before running this script.
# - Run only in an isolated lab/class environment, not production.
# - Pass all options on the command line; the script does not display menus.
# - Run with --dry-run first to review the install/configuration plan.
# - Status: Lab reference. Keep with docs; not production automation.

set -Eeuo pipefail

DB_NAME="dvwa"
DB_USER="dvwa"
DB_PASSWORD=""
WEB_ROOT="/var/www/html"
DVWA_DIR="dvwa"
DVWA_REPO="https://github.com/digininja/DVWA.git"
SERVER_NAME="_"
DRY_RUN="false"
SKIP_APT_UPDATE="false"

usage() {
  cat <<'USAGE'
Missing required arguments or invalid option.

Usage:
  sudo ./setup-dvwa-lab-target.sh --db-password '<lab-password>' --dry-run
  sudo ./setup-dvwa-lab-target.sh --db-password '<lab-password>'

Options:
  --db-name <name>       MariaDB database name. Default: dvwa
  --db-user <name>       MariaDB database user. Default: dvwa
  --db-password <value>  MariaDB database password. Required.
  --web-root <path>      Apache web root. Default: /var/www/html
  --dvwa-dir <name>      DVWA directory under web root. Default: dvwa
  --server-name <name>   Apache ServerName value. Default: _
  --skip-apt-update      Do not run apt update before package installation.
  --dry-run              Print the plan and commands without changing the host.
  -h, --help             Show this help.
USAGE
}

log() {
  printf '[DVWA lab setup] %s\n' "$*"
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
      --db-name)
        DB_NAME="${2:-}"
        shift 2
        ;;
      --db-user)
        DB_USER="${2:-}"
        shift 2
        ;;
      --db-password)
        DB_PASSWORD="${2:-}"
        shift 2
        ;;
      --web-root)
        WEB_ROOT="${2:-}"
        shift 2
        ;;
      --dvwa-dir)
        DVWA_DIR="${2:-}"
        shift 2
        ;;
      --server-name)
        SERVER_NAME="${2:-}"
        shift 2
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
  if [[ -z "$DB_NAME" || -z "$DB_USER" || -z "$DB_PASSWORD" || -z "$WEB_ROOT" || -z "$DVWA_DIR" ]]; then
    usage
    exit 2
  fi

  if [[ "$DB_NAME" =~ [^A-Za-z0-9_] || "$DB_USER" =~ [^A-Za-z0-9_] ]]; then
    log "Database name and user may contain only letters, numbers, and underscores."
    exit 2
  fi

  if [[ "$DB_PASSWORD" == *"'"* || "$DB_PASSWORD" == *"\\"* || "$DB_PASSWORD" == *"/"* || "$DB_PASSWORD" == *"&"* ]]; then
    log "For this lab script, choose a DB password without single quotes, backslashes, slashes, or ampersands."
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
DVWA lab setup plan:
  Database name:    ${DB_NAME}
  Database user:    ${DB_USER}
  Password provided: true
  Web root:         ${WEB_ROOT}
  DVWA directory:   ${DVWA_DIR}
  DVWA repo:        ${DVWA_REPO}
  ServerName:       ${SERVER_NAME}
  Run apt update:   $([[ "$SKIP_APT_UPDATE" == "true" ]] && echo "false" || echo "true")
  Dry run:          ${DRY_RUN}
EOF
}

install_dvwa() {
  if [[ "$SKIP_APT_UPDATE" != "true" ]]; then
    run_cmd apt-get update
  fi
  run_cmd env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2 \
    ca-certificates \
    git \
    libapache2-mod-php \
    mariadb-client \
    mariadb-server \
    php \
    php-gd \
    php-mysqli \
    php-xml

  run_cmd systemctl enable --now apache2 mariadb

  if [[ "$DRY_RUN" == "true" ]]; then
    log "Would create MariaDB database '${DB_NAME}' and user '${DB_USER}' without printing the password."
  else
    mysql --protocol=socket <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
  fi

  run_cmd install -d -m 0755 "$WEB_ROOT"
  if [[ ! -d "${WEB_ROOT}/${DVWA_DIR}/.git" ]]; then
    run_cmd git clone --depth 1 "$DVWA_REPO" "${WEB_ROOT}/${DVWA_DIR}"
  else
    run_cmd git -C "${WEB_ROOT}/${DVWA_DIR}" pull --ff-only
  fi

  run_cmd cp "${WEB_ROOT}/${DVWA_DIR}/config/config.inc.php.dist" "${WEB_ROOT}/${DVWA_DIR}/config/config.inc.php"
  run_cmd sed -i "s/^\$_DVWA\[ 'db_database' \].*/\$_DVWA[ 'db_database' ] = '${DB_NAME}';/" "${WEB_ROOT}/${DVWA_DIR}/config/config.inc.php"
  run_cmd sed -i "s/^\$_DVWA\[ 'db_user' \].*/\$_DVWA[ 'db_user' ] = '${DB_USER}';/" "${WEB_ROOT}/${DVWA_DIR}/config/config.inc.php"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "Would update DVWA database password in config.inc.php without printing it."
  else
    sed -i "s/^\$_DVWA\[ 'db_password' \].*/\$_DVWA[ 'db_password' ] = '${DB_PASSWORD}';/" "${WEB_ROOT}/${DVWA_DIR}/config/config.inc.php"
  fi

  run_cmd chown -R www-data:www-data "${WEB_ROOT}/${DVWA_DIR}"
  run_cmd find "${WEB_ROOT}/${DVWA_DIR}" -type d -exec chmod 0755 {} \;
  run_cmd find "${WEB_ROOT}/${DVWA_DIR}" -type f -exec chmod 0644 {} \;

  write_file /etc/apache2/sites-available/dvwa-lab.conf \
"<VirtualHost *:80>
    ServerName ${SERVER_NAME}
    DocumentRoot ${WEB_ROOT}/${DVWA_DIR}

    <Directory ${WEB_ROOT}/${DVWA_DIR}>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>"

  run_cmd a2enmod rewrite
  run_cmd a2dissite 000-default.conf
  run_cmd a2ensite dvwa-lab.conf
  run_cmd systemctl reload apache2
}

main() {
  parse_args "$@"
  validate_args
  print_plan
  install_dvwa
  local lab_ip
  lab_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  cat <<EOF
DVWA lab target setup complete.

URL: http://${lab_ip:-<lab-ip-address>}/

Open the DVWA setup page in a browser and click "Create / Reset Database".
Default DVWA credentials are documented by the DVWA project.
EOF
}

main "$@"
