#!/usr/bin/env bash
set -Eeuo pipefail

trap 'echo ""; echo "Erreur à la ligne $LINENO. L installation s arrête." >&2' ERR

if [[ "${EUID}" -ne 0 ]]; then
    echo "Lance ce script avec sudo : sudo ./install.sh"
    exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGE_FILE="${APP_DIR}/manage.py"
SETTINGS_FILE="${APP_DIR}/CVEye/settings.py"
REQ_FILE="${APP_DIR}/requirements.txt"
REQ_UTF8="${APP_DIR}/.requirements_utf8.txt"
VENV_DIR="${APP_DIR}/.venv"

SERVICE_NAME="cveye"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

NGINX_NAME="cveye"
NGINX_FILE="/etc/nginx/sites-available/${NGINX_NAME}"

ENV_DIR="/etc/cveye"
ENV_FILE="${ENV_DIR}/cveye.env"
CRON_FILE="/etc/cron.d/cveye_scans"
CRON_LOG="/var/log/cveye_scans.log"

STATIC_BASE="/var/www/cveye"
STATIC_ROOT="${STATIC_BASE}/staticfiles"
ACME_ROOT="/var/www/certbot"

DB_NAME="cveye_db"
DB_USER="cveye_user"
DB_HOST="127.0.0.1"
DB_PORT="5432"

DOMAIN_1="cveye.ovh"
DOMAIN_2="www.cveye.ovh"
DOMAIN_3="app.cveye.ovh"

APP_USER="${SUDO_USER:-}"
if [[ -z "${APP_USER}" || "${APP_USER}" == "root" ]]; then
    echo "Exécute ce script depuis ton compte normal avec sudo."
    echo "Exemple : sudo ./install.sh"
    exit 1
fi
APP_GROUP="$(id -gn "${APP_USER}")"

if [[ ! -f "${MANAGE_FILE}" ]]; then
    echo "manage.py introuvable."
    echo "Place install.sh à la racine du projet trunk, puis relance."
    exit 1
fi

if [[ ! -f "${SETTINGS_FILE}" ]]; then
    echo "Fichier settings.py introuvable : ${SETTINGS_FILE}"
    exit 1
fi

if [[ ! -f "${REQ_FILE}" ]]; then
    echo "requirements.txt introuvable : ${REQ_FILE}"
    exit 1
fi

echo "Projet détecté dans : ${APP_DIR}"
echo ""

read -r -s -p "Mot de passe PostgreSQL pour ${DB_USER} : " DB_PASSWORD
echo ""
while [[ -z "${DB_PASSWORD}" ]]; do
    read -r -s -p "Le mot de passe ne peut pas être vide. Réessaie : " DB_PASSWORD
    echo ""
done

read -r -p "Email Certbot (laisser vide pour une VM locale) : " CERTBOT_EMAIL

echo ""
echo "Installation des paquets système..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    software-properties-common \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    nginx \
    postgresql \
    postgresql-contrib \
    cron \
    build-essential \
    libpq-dev

if ! command -v python3.12 >/dev/null 2>&1; then
    echo "Python 3.12 absent, installation..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y python3.12 python3.12-venv python3.12-dev; then
        add-apt-repository -y ppa:deadsnakes/ppa
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y python3.12 python3.12-venv python3.12-dev
    fi
fi

systemctl enable --now postgresql
systemctl enable --now cron
systemctl enable nginx

echo ""
echo "Version Python utilisée :"
python3.12 --version

echo ""
echo "Conversion de requirements.txt en UTF-8 si nécessaire..."
python3.12 - "$REQ_FILE" "$REQ_UTF8" <<'PY'
from pathlib import Path
import sys

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
data = src.read_bytes()

if b"\x00" in data[:200]:
    text = data.decode("utf-16")
else:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")

dst.write_text(text, encoding="utf-8")
print(f"requirements prêt : {dst}")
PY

echo ""
echo "Création de l environnement virtuel avec Python 3.12..."
rm -rf "${VENV_DIR}"
python3.12 -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"

echo "Installation des dépendances Python..."
pip install --upgrade pip setuptools wheel
pip install -r "${REQ_UTF8}"
pip install gunicorn

echo ""
echo "Génération de la clé secrète Django..."
SECRET_KEY="$(python - <<'PY'
import secrets
print(secrets.token_urlsafe(64))
PY
)"

mkdir -p "${ENV_DIR}" "${STATIC_ROOT}" "${ACME_ROOT}"

python3.12 - "$ENV_FILE" "${APP_DIR}/.env" "$SECRET_KEY" "$DB_PASSWORD" "$STATIC_ROOT" <<'PY'
from pathlib import Path
import sys

targets = [Path(sys.argv[1]), Path(sys.argv[2])]
secret = sys.argv[3]
db_password = sys.argv[4]
static_root = sys.argv[5]

values = {
    "DJANGO_SECRET_KEY": secret,
    "DJANGO_DEBUG": "False",
    "DJANGO_FORCE_HTTPS": "False",
    "DB_NAME": "cveye_db",
    "DB_USER": "cveye_user",
    "DB_PASSWORD": db_password,
    "DB_HOST": "127.0.0.1",
    "DB_PORT": "5432",
    "DJANGO_STATIC_ROOT": static_root,
    "SCAN_MAX_THREADS": "5000",
}

def shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"

content = "\n".join(f"{k}={shell_quote(v)}" for k, v in values.items()) + "\n"

for target in targets:
    target.write_text(content, encoding="utf-8")
PY

chmod 600 "${ENV_FILE}" "${APP_DIR}/.env"
chown root:root "${ENV_FILE}"
chown "${APP_USER}:${APP_GROUP}" "${APP_DIR}/.env"

echo ""
echo "Sauvegarde et patch de CVEye/settings.py..."
cp "${SETTINGS_FILE}" "${SETTINGS_FILE}.bak.$(date +%Y%m%d%H%M%S)"

python3.12 - "${SETTINGS_FILE}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

if "import os" not in text:
    text = "import os\n" + text

text, n = re.subn(
    r"^SECRET_KEY\s*=\s*.*$",
    'SECRET_KEY = os.getenv("DJANGO_SECRET_KEY")',
    text,
    count=1,
    flags=re.MULTILINE,
)
if n == 0:
    text += '\nSECRET_KEY = os.getenv("DJANGO_SECRET_KEY")\n'

text, n = re.subn(
    r"^DEBUG\s*=\s*.*$",
    'DEBUG = os.getenv("DJANGO_DEBUG", "False").lower() == "true"',
    text,
    count=1,
    flags=re.MULTILINE,
)
if n == 0:
    text += '\nDEBUG = os.getenv("DJANGO_DEBUG", "False").lower() == "true"\n'

text, n = re.subn(
    r"^STATIC_URL\s*=\s*.*$",
    "STATIC_URL = '/static/'",
    text,
    count=1,
    flags=re.MULTILINE,
)
if n == 0:
    text += "\nSTATIC_URL = '/static/'\n"

text, n = re.subn(
    r"^STATIC_ROOT\s*=\s*.*$",
    'STATIC_ROOT = os.getenv("DJANGO_STATIC_ROOT", "/var/www/cveye/staticfiles")',
    text,
    count=1,
    flags=re.MULTILINE,
)
if n == 0:
    text += '\nSTATIC_ROOT = os.getenv("DJANGO_STATIC_ROOT", "/var/www/cveye/staticfiles")\n'

if "SECURE_PROXY_SSL_HEADER" not in text:
    text += '\nSECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")\n'
if "USE_X_FORWARDED_HOST" not in text:
    text += 'USE_X_FORWARDED_HOST = True\n'
if "SECURE_SSL_REDIRECT" not in text:
    text += 'SECURE_SSL_REDIRECT = os.getenv("DJANGO_FORCE_HTTPS", "False").lower() == "true"\n'
if "SESSION_COOKIE_SECURE" not in text:
    text += 'SESSION_COOKIE_SECURE = os.getenv("DJANGO_FORCE_HTTPS", "False").lower() == "true"\n'
if "CSRF_COOKIE_SECURE" not in text:
    text += 'CSRF_COOKIE_SECURE = os.getenv("DJANGO_FORCE_HTTPS", "False").lower() == "true"\n'

if "CSRF_TRUSTED_ORIGINS" not in text:
    text += '\nCSRF_TRUSTED_ORIGINS = [\n'
    text += '    "https://cveye.ovh",\n'
    text += '    "https://www.cveye.ovh",\n'
    text += '    "https://app.cveye.ovh",\n'
    text += ']\n'

path.write_text(text, encoding="utf-8")
PY

echo ""
echo "Configuration PostgreSQL..."
DB_PASSWORD_SQL="${DB_PASSWORD//\'/\'\'}"

sudo -u postgres psql <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}'
    ) THEN
        CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD_SQL}';
    ELSE
        ALTER ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASSWORD_SQL}';
    END IF;
END
\$\$;

SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = '${DB_NAME}'
)\gexec

GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
SQL

echo ""
echo "Préparation des droits..."
mkdir -p "${STATIC_ROOT}"
chown -R "${APP_USER}:${APP_GROUP}" "${STATIC_BASE}"
chmod 755 "${STATIC_BASE}" "${STATIC_ROOT}"
chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"

echo ""
echo "Migrations Django + collectstatic..."
su - "${APP_USER}" -s /bin/bash -c "
    cd '${APP_DIR}'
    set -a && source '${APP_DIR}/.env' && set +a
    source '${VENV_DIR}/bin/activate'
    python manage.py migrate --noinput
    python manage.py collectstatic --noinput
    python manage.py check --deploy || true
"

chmod -R a+rX "${STATIC_ROOT}"

echo ""
echo "Création du service systemd..."
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=CVEye Gunicorn
After=network.target postgresql.service

[Service]
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/gunicorn CVEye.wsgi:application --workers 3 --bind 127.0.0.1:8000 --access-logfile - --error-logfile -
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

echo ""
echo "Configuration Nginx..."
if systemctl is-active --quiet apache2; then
    systemctl disable --now apache2 || true
fi

cat > "${NGINX_FILE}" <<EOF
server {
    listen 80 default_server;
    server_name _ localhost 127.0.0.1 ${DOMAIN_1} ${DOMAIN_2} ${DOMAIN_3};

    client_max_body_size 20M;

    location /.well-known/acme-challenge/ {
        root ${ACME_ROOT};
    }

    location /static/ {
        alias ${STATIC_ROOT}/;
        access_log off;
        expires 7d;
        add_header Cache-Control "public";
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
    }
}
EOF

rm -f /etc/nginx/sites-enabled/default
ln -sfn "${NGINX_FILE}" "/etc/nginx/sites-enabled/${NGINX_NAME}"

nginx -t
systemctl restart nginx

echo ""
echo "Configuration du cron pour les scans planifiés..."
touch "${CRON_LOG}"
chown "${APP_USER}:${APP_GROUP}" "${CRON_LOG}"

cat > "${CRON_FILE}" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * ${APP_USER} cd ${APP_DIR} && set -a && source ${ENV_FILE} && set +a && ${VENV_DIR}/bin/python manage.py run_scheduled_scans >> ${CRON_LOG} 2>&1
EOF

chmod 644 "${CRON_FILE}"
systemctl restart cron

if [[ -n "${CERTBOT_EMAIL}" ]]; then
    echo ""
    echo "Installation de Certbot..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-nginx

    echo "Tentative d activation HTTPS..."
    if certbot --nginx --non-interactive --agree-tos --redirect -m "${CERTBOT_EMAIL}" \
        -d "${DOMAIN_1}" -d "${DOMAIN_2}" -d "${DOMAIN_3}"; then
        sed -i "s/^DJANGO_FORCE_HTTPS=.*/DJANGO_FORCE_HTTPS='True'/" "${ENV_FILE}" "${APP_DIR}/.env"
        systemctl restart "${SERVICE_NAME}"
        nginx -t
        systemctl restart nginx
        echo "HTTPS activé."
    else
        echo "Certbot a échoué."
        echo "Sur une VM locale, c est normal. Laisse simplement le champ email vide."
    fi
else
    echo ""
    echo "Certbot ignoré pour ce test local."
fi

echo ""
echo "Vérification rapide des statiques..."
if [[ -f "${STATIC_ROOT}/app_dashboard/css/scans_page.css" ]]; then
    echo "CSS principal détecté : ${STATIC_ROOT}/app_dashboard/css/scans_page.css"
else
    echo "Attention : CSS app_dashboard introuvable dans ${STATIC_ROOT}"
fi

echo ""
echo "État des services :"
systemctl --no-pager --full status "${SERVICE_NAME}" | sed -n '1,12p' || true
echo ""
systemctl --no-pager --full status nginx | sed -n '1,12p' || true

echo ""
echo "Installation terminée."
echo "Depuis la VM : ouvre http://127.0.0.1"
echo "Depuis Windows avec redirection de port 8080 -> 80 : ouvre http://127.0.0.1:8080"
echo ""
echo "Pour créer un compte admin ensuite :"
echo "cd ${APP_DIR} && source ${VENV_DIR}/bin/activate && python manage.py createsuperuser"