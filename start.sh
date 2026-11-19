#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

config_file=".soc-network.env"
config_tmp=""
unit_tmp=""
cleanup() {
  if [[ -n "$config_tmp" ]]; then
    rm -f -- "$config_tmp"
  fi
  if [[ -n "$unit_tmp" ]]; then
    rm -f -- "$unit_tmp"
  fi
}
trap cleanup EXIT

if [[ -L "$config_file" ]]; then
  echo "Refus de lire une configuration réseau qui est un lien symbolique : $config_file" >&2
  exit 1
fi

if [[ -f "$config_file" ]]; then
  chmod 600 "$config_file"
  # shellcheck disable=SC1090
  source "$config_file"
else
  if [[ ! -t 0 ]]; then
    echo "Première configuration interactive requise. Lancez ./start.sh depuis un terminal." >&2
    exit 1
  fi

  SOC_START_BIND_HOST="0.0.0.0"
  SOC_START_PUBLIC_HOST="${SOC_PUBLIC_HOST:-}"
  SOC_START_TLS_CERT_FILE="${SOC_TLS_CERT_FILE:-}"
  SOC_START_TLS_KEY_FILE="${SOC_TLS_KEY_FILE:-}"
  SOC_START_CREDENTIAL_KEY_FILE="${SOC_CREDENTIAL_KEY_FILE:-}"

  if [[ -z "$SOC_START_PUBLIC_HOST" ]]; then
    read -r -p "Nom DNS couvert par le certificat (ex. soc.example.lan) : " SOC_START_PUBLIC_HOST
  fi
  if [[ -z "$SOC_START_TLS_CERT_FILE" ]]; then
    read -r -p "Chemin du certificat TLS : " SOC_START_TLS_CERT_FILE
  fi
  if [[ -z "$SOC_START_TLS_KEY_FILE" ]]; then
    read -r -p "Chemin de la clé privée TLS : " SOC_START_TLS_KEY_FILE
  fi
  if [[ -z "$SOC_START_CREDENTIAL_KEY_FILE" ]]; then
    read -r -p "Clé Wazuh SOC_CREDENTIAL_KEY_FILE (Entrée si Wazuh n'est pas encore configuré) : " SOC_START_CREDENTIAL_KEY_FILE
  fi

  if [[ ! "$SOC_START_PUBLIC_HOST" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ||
        "$SOC_START_PUBLIC_HOST" == *..* ]]; then
    echo "Le nom DNS est invalide." >&2
    exit 1
  fi
  if [[ ! -f "$SOC_START_TLS_CERT_FILE" || ! -r "$SOC_START_TLS_CERT_FILE" ]]; then
    echo "Certificat introuvable ou illisible : $SOC_START_TLS_CERT_FILE" >&2
    exit 1
  fi
  if [[ ! -f "$SOC_START_TLS_KEY_FILE" || ! -r "$SOC_START_TLS_KEY_FILE" ]]; then
    echo "Clé privée introuvable ou illisible : $SOC_START_TLS_KEY_FILE" >&2
    exit 1
  fi

  SOC_START_SERVICE_NAME=""
fi

SOC_HOST="${SOC_HOST:-${SOC_START_BIND_HOST:-0.0.0.0}}"
SOC_PUBLIC_HOST="${SOC_PUBLIC_HOST:-${SOC_START_PUBLIC_HOST:-}}"
SOC_TLS_CERT_FILE="${SOC_TLS_CERT_FILE:-${SOC_START_TLS_CERT_FILE:-}}"
SOC_TLS_KEY_FILE="${SOC_TLS_KEY_FILE:-${SOC_START_TLS_KEY_FILE:-}}"
SOC_CREDENTIAL_KEY_FILE="${SOC_CREDENTIAL_KEY_FILE:-${SOC_START_CREDENTIAL_KEY_FILE:-}}"

if [[ -z "$SOC_PUBLIC_HOST" || -z "$SOC_TLS_CERT_FILE" || -z "$SOC_TLS_KEY_FILE" ]]; then
  echo "Le nom DNS et les chemins du certificat et de la clé TLS sont requis." >&2
  exit 1
fi
if [[ ! -f "$SOC_TLS_CERT_FILE" || ! -r "$SOC_TLS_CERT_FILE" ]]; then
  echo "Certificat introuvable ou illisible : $SOC_TLS_CERT_FILE" >&2
  exit 1
fi
if [[ ! -f "$SOC_TLS_KEY_FILE" || ! -r "$SOC_TLS_KEY_FILE" ]]; then
  echo "Clé privée introuvable ou illisible : $SOC_TLS_KEY_FILE" >&2
  exit 1
fi
if [[ -n "$SOC_CREDENTIAL_KEY_FILE" &&
      ( ! -f "$SOC_CREDENTIAL_KEY_FILE" || ! -r "$SOC_CREDENTIAL_KEY_FILE" ) ]]; then
  echo "Clé de chiffrement Wazuh introuvable ou illisible : $SOC_CREDENTIAL_KEY_FILE" >&2
  exit 1
fi

export SOC_HOST SOC_TLS_CERT_FILE SOC_TLS_KEY_FILE
if [[ -n "$SOC_CREDENTIAL_KEY_FILE" ]]; then
  export SOC_CREDENTIAL_KEY_FILE
fi

save_local_config() {
  mkdir -p "$(dirname "$config_file")"
  config_tmp="$(mktemp "${config_file}.XXXXXX")"
  {
    printf 'SOC_START_BIND_HOST=%q\n' "$SOC_START_BIND_HOST"
    printf 'SOC_START_PUBLIC_HOST=%q\n' "$SOC_START_PUBLIC_HOST"
    printf 'SOC_START_TLS_CERT_FILE=%q\n' "$SOC_START_TLS_CERT_FILE"
    printf 'SOC_START_TLS_KEY_FILE=%q\n' "$SOC_START_TLS_KEY_FILE"
    printf 'SOC_START_CREDENTIAL_KEY_FILE=%q\n' "$SOC_START_CREDENTIAL_KEY_FILE"
    printf 'SOC_START_SERVICE_NAME=%q\n' "$SOC_START_SERVICE_NAME"
  } > "$config_tmp"
  chmod 600 "$config_tmp"
  mv "$config_tmp" "$config_file"
  config_tmp=""
}

install_systemd_service() {
  local service_name="$1"
  local service_user
  local service_group
  local repo_dir
  local unit_path

  if [[ "$(id -u)" -eq 0 ]]; then
    echo "Lancez start.sh avec un compte normal, pas avec sudo ; sudo sera utilisé pour installer le service." >&2
    return 1
  fi
  if ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
    echo "systemd n'est pas disponible ; le service n'a pas été créé." >&2
    return 1
  fi
  if [[ "$PWD" == *[[:space:]]* ]]; then
    echo "Le dépôt doit être installé dans un chemin sans espaces pour systemd : $PWD" >&2
    return 1
  fi
  if ! command -v sudo >/dev/null; then
    echo "sudo est nécessaire pour installer le service systemd." >&2
    return 1
  fi
  sudo -v

  service_user="$(id -un)"
  service_group="$(id -gn)"
  repo_dir="$PWD"
  unit_path="/etc/systemd/system/${service_name}.service"
  if sudo test -e "$unit_path"; then
    echo "Le service existe déjà : $unit_path" >&2
    return 1
  fi

  unit_tmp="$(mktemp)"
  cat > "$unit_tmp" <<EOF
[Unit]
Description=Go SOC Backend (${service_name})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${service_user}
Group=${service_group}
WorkingDirectory=${repo_dir}
EnvironmentFile=-${repo_dir}/.soc-service.env
ExecStart=/bin/bash ${repo_dir}/start.sh
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
  sudo install -m 0644 "$unit_tmp" "$unit_path"
  sudo systemctl daemon-reload
  sudo systemctl enable --now "${service_name}.service"
}

if [[ -z "${SOC_START_BIND_HOST:-}" ]]; then
  SOC_START_BIND_HOST="$SOC_HOST"
fi
SOC_START_PUBLIC_HOST="${SOC_START_PUBLIC_HOST:-$SOC_PUBLIC_HOST}"
SOC_START_TLS_CERT_FILE="${SOC_START_TLS_CERT_FILE:-$SOC_TLS_CERT_FILE}"
SOC_START_TLS_KEY_FILE="${SOC_START_TLS_KEY_FILE:-$SOC_TLS_KEY_FILE}"
SOC_START_CREDENTIAL_KEY_FILE="${SOC_START_CREDENTIAL_KEY_FILE:-$SOC_CREDENTIAL_KEY_FILE}"
SOC_START_SERVICE_NAME="${SOC_START_SERVICE_NAME:-}"

if [[ -z "${INVOCATION_ID:-}" && -t 0 ]] &&
   command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
  service_name_was_saved="$SOC_START_SERVICE_NAME"
  if [[ -z "$SOC_START_SERVICE_NAME" ]]; then
    read -r -p "Nom du service systemd [go-soc-backend] : " SOC_START_SERVICE_NAME
    SOC_START_SERVICE_NAME="${SOC_START_SERVICE_NAME:-go-soc-backend}"
  fi
  if [[ ! "$SOC_START_SERVICE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
    echo "Nom de service invalide ; utilisez lettres, chiffres, tirets ou soulignés." >&2
    exit 1
  fi

  unit_path="/etc/systemd/system/${SOC_START_SERVICE_NAME}.service"
  if [[ -f "$unit_path" ]]; then
    if [[ -z "$service_name_was_saved" ]]; then
      echo "Ce nom de service existe déjà ; choisissez un autre nom." >&2
      exit 1
    fi
    echo "Le service ${SOC_START_SERVICE_NAME}.service existe déjà."
    sudo systemctl start "${SOC_START_SERVICE_NAME}.service"
    exit 0
  fi

  read -r -p "Créer et démarrer ce service maintenant ? [O/n] " install_answer
  case "$install_answer" in
    n|N|non|Non|NON)
      SOC_START_SERVICE_NAME=""
      ;;
    *)
      save_local_config
      install_systemd_service "$SOC_START_SERVICE_NAME"
      printf 'Tableau de bord : https://%s:%s/\n' "$SOC_PUBLIC_HOST" "${SOC_PORT:-8080}"
      echo "Service installé. Consultez ses journaux avec : sudo journalctl -u ${SOC_START_SERVICE_NAME}.service -f"
      exit 0
      ;;
  esac
fi

if [[ ! -f "$config_file" ]]; then
  save_local_config
fi

printf 'Tableau de bord : https://%s:%s/\n' "$SOC_PUBLIC_HOST" "${SOC_PORT:-8080}"
echo "L’écoute réseau est protégée par TLS et limitée par votre pare-feu."
echo "Pour créer le premier compte admin à distance, utilisez un tunnel SSH vers le port 8080."
exec /usr/bin/go run ./cmd/soc-backend
