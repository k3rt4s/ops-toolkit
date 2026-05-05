#!/usr/bin/env bash
# Instructions
# - Purpose: Install DVWA on an Ubuntu/Debian lab target host.
# - Read the root README.md before running this script.
# - Run only in an isolated lab/class environment, not production.
# - Pass all options on the command line; the script does not display menus.
# - Status: Lab reference. Keep with docs; not production automation.

set -Eeuo pipefail

DB_NAME="dvwa"
DB_USER="dvwa"
DB_PASSWORD=""
WEB_ROOT="/var/www/html"
DVWA_DIR="dvwa"
DVWA_REPO="https://github.com/digininja/DVWA.git"
SERVER_NAME="_"

usage() {
  cat <<'USAGE'
Missing required arguments or invalid option.

Usage:
  sudo ./setup-dvwa-lab-target.sh --db-password '<lab-password>'

Options:
  --db-name <name>       MariaDB database name. Default: dvwa
  --db-user <name>       MariaDB database user. Default: dvwa
  --db-password <value>  MariaDB database password. Required.
  --web-root <path>      Apache web root. Default: /var/www/html
  --dvwa-dir <name>      DVWA directory under web root. Default: dvwa
  --server-name <name>   Apache ServerName value. Default: _
  -h, --help             Show this help.
USAGE
}

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

if [[ -z "$DB_NAME" || -z "$DB_USER" || -z "$DB_PASSWORD" || -z "$WEB_ROOT" || -z "$DVWA_DIR" ]]; then
  usage
  exit 2
fi

if [[ "$DB_NAME" =~ [^A-Za-z0-9_] || "$DB_USER" =~ [^A-Za-z0-9_] ]]; then
  echo "Database name and user may contain only letters, numbers, and underscores." >&2
  exit 2
fi

if [[ "$DB_PASSWORD" == *"'"* || "$DB_PASSWORD" == *"\\"* || "$DB_PASSWORD" == *"/"* || "$DB_PASSWORD" == *"&"* ]]; then
  echo "For this lab script, choose a DB password without single quotes, backslashes, slashes, or ampersands." >&2
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

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
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

systemctl enable --now apache2 mariadb

mysql --protocol=socket <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

install -d -m 0755 "$WEB_ROOT"
if [[ ! -d "${WEB_ROOT}/${DVWA_DIR}/.git" ]]; then
  git clone --depth 1 "$DVWA_REPO" "${WEB_ROOT}/${DVWA_DIR}"
else
  git -C "${WEB_ROOT}/${DVWA_DIR}" pull --ff-only
fi

cp "${WEB_ROOT}/${DVWA_DIR}/config/config.inc.php.dist" "${WEB_ROOT}/${DVWA_DIR}/config/config.inc.php"
sed -i "s/^\$_DVWA\[ 'db_database' \].*/\$_DVWA[ 'db_database' ] = '${DB_NAME}';/" "${WEB_ROOT}/${DVWA_DIR}/config/config.inc.php"
sed -i "s/^\$_DVWA\[ 'db_user' \].*/\$_DVWA[ 'db_user' ] = '${DB_USER}';/" "${WEB_ROOT}/${DVWA_DIR}/config/config.inc.php"
sed -i "s/^\$_DVWA\[ 'db_password' \].*/\$_DVWA[ 'db_password' ] = '${DB_PASSWORD}';/" "${WEB_ROOT}/${DVWA_DIR}/config/config.inc.php"

chown -R www-data:www-data "${WEB_ROOT}/${DVWA_DIR}"
find "${WEB_ROOT}/${DVWA_DIR}" -type d -exec chmod 0755 {} \;
find "${WEB_ROOT}/${DVWA_DIR}" -type f -exec chmod 0644 {} \;

cat > /etc/apache2/sites-available/dvwa-lab.conf <<EOF
<VirtualHost *:80>
    ServerName ${SERVER_NAME}
    DocumentRoot ${WEB_ROOT}/${DVWA_DIR}

    <Directory ${WEB_ROOT}/${DVWA_DIR}>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

a2enmod rewrite
a2dissite 000-default.conf
a2ensite dvwa-lab.conf
systemctl reload apache2

cat <<EOF
DVWA lab target setup complete.

URL: http://$(hostname -I | awk '{print $1}')/

Open the DVWA setup page in a browser and click "Create / Reset Database".
Default DVWA credentials are documented by the DVWA project.
EOF
