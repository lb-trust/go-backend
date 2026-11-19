#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

config_file=".soc-network.env"
config_tmp=""
unit_tmp=""
tls_cert_tmp=""
tls_key_tmp=""
cleanup() {
  if [[ -n "$config_tmp" ]]; then
    rm -f -- "$config_tmp"
  fi
  if [[ -n "$unit_tmp" ]]; then
    rm -f -- "$unit_tmp"
  fi
  if [[ -n "$tls_cert_tmp" ]]; then
    rm -f -- "$tls_cert_tmp"
  fi
  if [[ -n "$tls_key_tmp" ]]; then
    rm -f -- "$tls_key_tmp"
  fi
}
trap cleanup EXIT

configure_network() {
  local certificate_choice
  local certificate_san
  local tls_dir
  local tls_suffix
  local setup_ip_input
  local input_value

  if [[ ! -t 0 ]]; then
    echo "La configuration interactive requiert un terminal. Lancez ./start.sh depuis un terminal." >&2
    return 1
  fi

  SOC_START_BIND_HOST="0.0.0.0"
  if [[ -z "$SOC_START_PUBLIC_HOST" ]]; then
    read -r -p "Nom DNS du serveur (ex. soc.example.lan) : " SOC_START_PUBLIC_HOST
  else
    read -r -p "Nom DNS du serveur [$SOC_START_PUBLIC_HOST] : " input_value
    SOC_START_PUBLIC_HOST="${input_value:-$SOC_START_PUBLIC_HOST}"
  fi
  if [[ ! "$SOC_START_PUBLIC_HOST" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ||
        "$SOC_START_PUBLIC_HOST" == *..* ]]; then
    echo "Le nom DNS est invalide." >&2
    return 1
  fi

  if [[ -n "$SOC_START_TLS_CERT_FILE" && -n "$SOC_START_TLS_KEY_FILE" ]]; then
    echo "Certificat TLS actuel : $SOC_START_TLS_CERT_FILE"
    echo "  0) Conserver ce certificat"
    echo "  1) Utiliser un autre certificat existant"
    echo "  2) Générer un nouveau certificat auto-signé"
    read -r -p "Choix [0] : " certificate_choice
    certificate_choice="${certificate_choice:-0}"
  else
    echo "Choisissez un certificat TLS :"
    echo "  1) Utiliser un certificat existant (Let's Encrypt ou autorité interne)"
    echo "  2) Générer automatiquement un certificat auto-signé (simple, mais non approuvé par défaut)"
    read -r -p "Choix [2] : " certificate_choice
    certificate_choice="${certificate_choice:-2}"
  fi

  case "$certificate_choice" in
    0)
      if [[ -z "$SOC_START_TLS_CERT_FILE" || -z "$SOC_START_TLS_KEY_FILE" ]]; then
        echo "Aucun certificat TLS existant à conserver." >&2
        return 1
      fi
      ;;
    1)
      read -r -p "Chemin du certificat TLS : " SOC_START_TLS_CERT_FILE
      read -r -p "Chemin de la clé privée TLS : " SOC_START_TLS_KEY_FILE
      ;;
    2)
      if ! command -v openssl >/dev/null; then
        echo "OpenSSL est requis pour générer le certificat. Installez-le puis relancez start.sh." >&2
        return 1
      fi
      tls_dir="$HOME/.config/go-backend/tls"
      mkdir -p "$tls_dir"
      chmod 700 "$tls_dir"
      tls_suffix=""
      if [[ -e "$tls_dir/server.crt" || -e "$tls_dir/server.key" ]]; then
        tls_suffix="-$(date +%Y%m%d%H%M%S)"
      fi
      SOC_START_TLS_CERT_FILE="$tls_dir/server${tls_suffix}.crt"
      SOC_START_TLS_KEY_FILE="$tls_dir/server${tls_suffix}.key"
      if [[ -e "$SOC_START_TLS_CERT_FILE" || -e "$SOC_START_TLS_KEY_FILE" ]]; then
        echo "Un certificat ou une clé existe déjà : $SOC_START_TLS_CERT_FILE" >&2
        return 1
      fi

      tls_cert_tmp="$(mktemp "$tls_dir/.server.crt.XXXXXX")"
      tls_key_tmp="$(mktemp "$tls_dir/.server.key.XXXXXX")"
      certificate_san="DNS:$SOC_START_PUBLIC_HOST"
      if [[ "$SOC_START_PUBLIC_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        certificate_san="IP:$SOC_START_PUBLIC_HOST"
      fi
      umask 077
      if ! openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
        -keyout "$tls_key_tmp" \
        -out "$tls_cert_tmp" \
        -subj "/CN=$SOC_START_PUBLIC_HOST" \
        -addext "subjectAltName=$certificate_san"; then
        echo "La génération du certificat TLS a échoué." >&2
        return 1
      fi
      chmod 600 "$tls_key_tmp"
      chmod 644 "$tls_cert_tmp"
      mv "$tls_key_tmp" "$SOC_START_TLS_KEY_FILE"
      tls_key_tmp=""
      mv "$tls_cert_tmp" "$SOC_START_TLS_CERT_FILE"
      tls_cert_tmp=""
      echo "Certificat auto-signé créé dans $tls_dir."
      echo "Certificat : $SOC_START_TLS_CERT_FILE"
      echo "Clé privée : $SOC_START_TLS_KEY_FILE"
      ;;
    *)
      echo "Choix invalide ; utilisez 0, 1 ou 2." >&2
      return 1
      ;;
  esac

  if [[ -n "$SOC_START_SETUP_ALLOWED_IP" ]]; then
    read -r -p "IP autorisée à créer le premier compte admin [$SOC_START_SETUP_ALLOWED_IP] (Entrée conserve, - désactive) : " setup_ip_input
  else
    read -r -p "IP autorisée à créer le premier compte admin (Entrée = accès local uniquement) : " setup_ip_input
  fi
  if [[ "$setup_ip_input" == "-" ]]; then
    SOC_START_SETUP_ALLOWED_IP=""
  elif [[ -n "$setup_ip_input" ]]; then
    SOC_START_SETUP_ALLOWED_IP="$setup_ip_input"
  fi
  if [[ -n "$SOC_START_SETUP_ALLOWED_IP" ]]; then
    if ! command -v python3 >/dev/null ||
      ! python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$SOC_START_SETUP_ALLOWED_IP" >/dev/null 2>&1; then
      echo "Adresse IP invalide ; saisissez une adresse IPv4 ou IPv6 exacte." >&2
      return 1
    fi
  fi

  if [[ -n "$SOC_START_CREDENTIAL_KEY_FILE" ]]; then
    read -r -p "Fichier de clé de chiffrement Wazuh [$SOC_START_CREDENTIAL_KEY_FILE] (- pour aucun) : " input_value
  else
    read -r -p "Fichier de clé SOC_CREDENTIAL_KEY_FILE (Entrée si Wazuh n'est pas encore configuré) : " input_value
  fi
  if [[ "$input_value" == "-" ]]; then
    SOC_START_CREDENTIAL_KEY_FILE=""
  elif [[ -n "$input_value" ]]; then
    SOC_START_CREDENTIAL_KEY_FILE="$input_value"
  fi

  if [[ ! -f "$SOC_START_TLS_CERT_FILE" || ! -r "$SOC_START_TLS_CERT_FILE" ]]; then
    echo "Certificat introuvable ou illisible : $SOC_START_TLS_CERT_FILE" >&2
    return 1
  fi
  if [[ ! -f "$SOC_START_TLS_KEY_FILE" || ! -r "$SOC_START_TLS_KEY_FILE" ]]; then
    echo "Clé privée introuvable ou illisible : $SOC_START_TLS_KEY_FILE" >&2
    return 1
  fi
  if [[ "$SOC_START_PUBLIC_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if ! openssl x509 -in "$SOC_START_TLS_CERT_FILE" -noout -checkip "$SOC_START_PUBLIC_HOST" >/dev/null 2>&1; then
      echo "Le certificat TLS ne couvre pas l'adresse IP $SOC_START_PUBLIC_HOST." >&2
      return 1
    fi
  elif ! openssl x509 -in "$SOC_START_TLS_CERT_FILE" -noout -checkhost "$SOC_START_PUBLIC_HOST" >/dev/null 2>&1; then
    echo "Le certificat TLS ne couvre pas le nom DNS $SOC_START_PUBLIC_HOST." >&2
    return 1
  fi
  if [[ -n "$SOC_START_CREDENTIAL_KEY_FILE" &&
        ( ! -f "$SOC_START_CREDENTIAL_KEY_FILE" || ! -r "$SOC_START_CREDENTIAL_KEY_FILE" ) ]]; then
    echo "Clé de chiffrement Wazuh introuvable ou illisible : $SOC_START_CREDENTIAL_KEY_FILE" >&2
    return 1
  fi
}

if [[ -L "$config_file" ]]; then
  echo "Refus de lire une configuration réseau qui est un lien symbolique : $config_file" >&2
  exit 1
fi

if [[ -f "$config_file" ]]; then
  chmod 600 "$config_file"
  # shellcheck disable=SC1090
  source "$config_file"
  SOC_START_BIND_HOST="${SOC_START_BIND_HOST:-0.0.0.0}"
  SOC_START_SETUP_ALLOWED_IP="${SOC_START_SETUP_ALLOWED_IP:-}"
  config_exists=1
else
  config_exists=0
  SOC_START_BIND_HOST="0.0.0.0"
  SOC_START_PUBLIC_HOST="${SOC_PUBLIC_HOST:-}"
  SOC_START_TLS_CERT_FILE="${SOC_TLS_CERT_FILE:-}"
  SOC_START_TLS_KEY_FILE="${SOC_TLS_KEY_FILE:-}"
  SOC_START_CREDENTIAL_KEY_FILE="${SOC_CREDENTIAL_KEY_FILE:-}"
  SOC_START_SETUP_ALLOWED_IP="${SOC_SETUP_ALLOWED_IP:-}"
  SOC_START_SERVICE_NAME=""
fi

config_reconfigure=0
if [[ "$config_exists" -eq 1 && -z "${INVOCATION_ID:-}" && -t 0 ]]; then
  echo "Une configuration existe déjà dans $config_file."
  read -r -p "  1) La conserver et démarrer le service  2) La modifier  3) Quitter [1] : " config_choice
  case "${config_choice:-1}" in
    1)
      ;;
    2)
      config_reconfigure=1
      ;;
    3|q|Q)
      exit 0
      ;;
    *)
      echo "Choix invalide ; utilisez 1, 2 ou 3." >&2
      exit 1
      ;;
  esac
fi

if [[ "$config_exists" -eq 0 || "$config_reconfigure" -eq 1 ]]; then
  if [[ ! -t 0 ]]; then
    echo "Première configuration interactive requise. Lancez ./start.sh depuis un terminal." >&2
    exit 1
  fi

  configure_network
fi

SOC_HOST="$SOC_START_BIND_HOST"
SOC_PUBLIC_HOST="$SOC_START_PUBLIC_HOST"
SOC_TLS_CERT_FILE="$SOC_START_TLS_CERT_FILE"
SOC_TLS_KEY_FILE="$SOC_START_TLS_KEY_FILE"
SOC_CREDENTIAL_KEY_FILE="$SOC_START_CREDENTIAL_KEY_FILE"
SOC_SETUP_ALLOWED_IP="$SOC_START_SETUP_ALLOWED_IP"

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

export SOC_HOST SOC_TLS_CERT_FILE SOC_TLS_KEY_FILE SOC_SETUP_ALLOWED_IP
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
    printf 'SOC_START_SETUP_ALLOWED_IP=%q\n' "$SOC_START_SETUP_ALLOWED_IP"
    printf 'SOC_START_SERVICE_NAME=%q\n' "$SOC_START_SERVICE_NAME"
  } > "$config_tmp"
  chmod 600 "$config_tmp"
  mv "$config_tmp" "$config_file"
  config_tmp=""
}

if [[ "$config_reconfigure" -eq 1 ]]; then
  save_local_config
  if [[ -n "$SOC_START_SERVICE_NAME" &&
        -d /run/systemd/system &&
        -f "/etc/systemd/system/${SOC_START_SERVICE_NAME}.service" ]]; then
    sudo systemctl restart "${SOC_START_SERVICE_NAME}.service"
    printf 'Configuration mise à jour. Tableau de bord : https://%s:%s/\n' "$SOC_PUBLIC_HOST" "${SOC_PORT:-8080}"
    echo "Le service ${SOC_START_SERVICE_NAME}.service a été redémarré."
    echo "Vérifiez son état avec : sudo systemctl status ${SOC_START_SERVICE_NAME}.service"
    exit 0
  fi
fi

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
      echo "Le nom « ${SOC_START_SERVICE_NAME} » est un service systemd, pas une commande à saisir seule."
      echo "État :       sudo systemctl status ${SOC_START_SERVICE_NAME}.service"
      echo "Journaux :   sudo journalctl -u ${SOC_START_SERVICE_NAME}.service -f"
      echo "Redémarrer : sudo systemctl restart ${SOC_START_SERVICE_NAME}.service"
      echo "Arrêter :    sudo systemctl stop ${SOC_START_SERVICE_NAME}.service"
      exit 0
      ;;
  esac
fi

if [[ ! -f "$config_file" ]]; then
  save_local_config
fi

printf 'Tableau de bord : https://%s:%s/\n' "$SOC_PUBLIC_HOST" "${SOC_PORT:-8080}"
echo "L’écoute réseau est protégée par TLS et limitée par votre pare-feu."
if [[ -n "$SOC_SETUP_ALLOWED_IP" ]]; then
  echo "La création initiale du compte admin est autorisée depuis $SOC_SETUP_ALLOWED_IP."
else
  echo "La création initiale du compte admin est réservée à une connexion locale."
fi
exec /usr/bin/go run ./cmd/soc-backend
