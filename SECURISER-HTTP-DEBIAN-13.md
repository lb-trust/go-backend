# Sécuriser l’accès HTTP sur Debian 13

Ce guide place le backend SOC derrière Nginx : le navigateur communique en
HTTPS avec Nginx, et Nginx communique en HTTP avec le backend sur la boucle
locale. Le port du backend n’est donc pas exposé au réseau.

```text
Navigateur ── HTTPS :443 ──> Nginx ── HTTP :8080 (localhost) ──> Backend SOC
```

Le backend ne gère pas lui-même TLS. Cette solution ne nécessite pas de
modifier son code.

## Prérequis

- Un serveur Debian 13 à jour et un compte disposant de `sudo`.
- Un nom DNS, par exemple `soc.example.com`, qui pointe vers ce serveur.
- Pour un certificat Let’s Encrypt avec le challenge HTTP-01 : les ports TCP
  80 et 443 doivent être joignables depuis Internet. Si le service reste sur un
  réseau privé sans entrée DNS publique, utilisez plutôt une autorité de
  certification interne ou un challenge DNS-01.
- Go 1.24 ou plus récent pour compiler le backend.

Remplacez `soc.example.com` par votre nom DNS dans toutes les commandes et
configurations ci-dessous.

## 1. Installer Nginx et Certbot

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
sudo systemctl enable --now nginx
```

Vérifiez que les enregistrements DNS A et, le cas échéant, AAAA pointent vers
la bonne machine. Ne publiez pas d’enregistrement IPv6 si le serveur ou son
pare-feu IPv6 n’est pas correctement configuré.

## 2. Créer un compte de service et le binaire

Exécutez ces commandes depuis la racine du dépôt :

```bash
go version
go build -trimpath -o /tmp/soc-backend ./cmd/soc-backend
sudo adduser --system --group --no-create-home --home /var/lib/soc-backend soc-backend
sudo install -d -o soc-backend -g soc-backend -m 0750 /var/lib/soc-backend
sudo install -o root -g root -m 0755 /tmp/soc-backend /usr/local/bin/soc-backend
rm /tmp/soc-backend
```

Le binaire embarque le dashboard et ses ressources. Le compte `soc-backend`
sert uniquement à exécuter le service ; il ne doit pas être utilisé pour une
connexion interactive.

## 3. Configurer les secrets et le backend

Créez un fichier de configuration lisible uniquement par root et le compte de
service :

```bash
sudo install -o root -g soc-backend -m 0640 /dev/null /etc/soc-backend.env
sudoedit /etc/soc-backend.env
```

Exemple de contenu :

```ini
SOC_HOST=127.0.0.1
SOC_PORT=8080
SOC_DB_PATH=/var/lib/soc-backend/soc.db
SOC_API_TOKEN_FILE=/var/lib/soc-backend/.soc-api-token
WAZUH_POLL_SECONDS=60
WAZUH_SOURCES_JSON={"tenant_id":"client-a","url":"https://indexer.example.lan:9200","username":"soc-reader","password":"REMPLACER","verify_tls":true,"alerts_index":"wazuh-alerts-*","batch_size":100}
```

`EnvironmentFile` systemd n’est pas un script shell : ne mettez pas `export`,
ne découpez pas le JSON sur plusieurs lignes et ne comptez pas sur les
substitutions shell. Gardez le secret réel uniquement dans ce fichier ou dans
un gestionnaire de secrets. Un compte Wazuh en lecture seule et TLS vérifié
sont requis. Si Ollama ou IRIS doivent être configurés, ajoutez leurs variables
au même fichier avec des secrets et certificats correctement protégés.

Créez `/etc/systemd/system/soc-backend.service` :

```ini
[Unit]
Description=Backend SOC
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=soc-backend
Group=soc-backend
WorkingDirectory=/var/lib/soc-backend
EnvironmentFile=/etc/soc-backend.env
ExecStart=/usr/local/bin/soc-backend
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
ReadWritePaths=/var/lib/soc-backend
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

Le service ne peut écrire que dans `/var/lib/soc-backend`. La base, le jeton
généré et les fichiers temporaires SQLite WAL/SHM y seront créés. Le binaire
reste détenu par root et ne peut pas être modifié par le compte de service.

Activez-le et vérifiez son état :

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now soc-backend
sudo systemctl status soc-backend --no-pager
sudo journalctl -u soc-backend -n 50 --no-pager
```

Vérifiez que le port écoute uniquement sur localhost :

```bash
sudo ss -lntp | grep ':8080'
curl --fail http://127.0.0.1:8080/health
```

Le résultat de `ss` doit montrer `127.0.0.1:8080` et non `0.0.0.0:8080` ou
`[::]:8080`. En cas d’échec, vérifiez `SOC_HOST`, les journaux systemd et les
permissions de `/var/lib/soc-backend`.

## 4. Obtenir le certificat TLS

Créez d’abord `/etc/nginx/sites-available/soc-backend` avec une configuration
HTTP temporaire :

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name soc.example.com;

    location / {
        return 301 https://soc.example.com$request_uri;
    }
}
```

Activez le site et vérifiez la configuration :

```bash
sudo ln -s /etc/nginx/sites-available/soc-backend /etc/nginx/sites-enabled/soc-backend
sudo nginx -t
sudo systemctl reload nginx
```

Si un site par défaut est activé et entre en conflit avec le nom DNS, désactivez
ce lien uniquement après avoir vérifié qu’il n’est pas utilisé par un autre
service. Demandez ensuite le certificat :

```bash
sudo certbot --nginx -d soc.example.com
```

Suivez les instructions Certbot avec une adresse de contact administrateur.
Choisissez la redirection vers HTTPS si elle est proposée. Certbot configure
normalement le renouvellement automatique ; le guide vérifie ce renouvellement
plus bas.

## 5. Configurer le reverse proxy HTTPS

Remplacez le contenu du site par cette configuration. Le bloc par défaut rejette
les noms d’hôtes non prévus ; le bloc HTTP redirige vers le nom canonique ; seul
le bloc HTTPS relaie le trafic à l’application.

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}

server {
    listen 80;
    listen [::]:80;
    server_name soc.example.com;
    return 301 https://soc.example.com$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name soc.example.com;

    ssl_certificate /etc/letsencrypt/live/soc.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.example.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Vérifiez puis rechargez Nginx :

```bash
sudo nginx -t
sudo systemctl reload nginx
```

N’effacez pas ni ne remplacez les fichiers TLS gérés par Certbot. Ne configurez
pas de `proxy_set_header Authorization ""` : le dashboard utilise le jeton API
dans cet en-tête pour ses appels authentifiés au backend.

Après vérification complète du HTTPS, vous pouvez ajouter dans le bloc HTTPS
un en-tête HSTS, par exemple :

```nginx
add_header Strict-Transport-Security "max-age=31536000" always;
```

HSTS force les navigateurs concernés à utiliser HTTPS pendant la durée indiquée.
N’ajoutez pas `includeSubDomains` ou `preload` avant d’avoir vérifié que tous
les sous-domaines concernés peuvent rester en HTTPS.

## 6. Limiter l’accès réseau

Le backend doit rester lié à `127.0.0.1`. N’ouvrez jamais le port 8080 dans le
pare-feu ou le pare-feu cloud. Seuls les ports 80 et 443 sont nécessaires pour
un site public utilisant le challenge HTTP-01 ; le port 80 sert uniquement à
rediriger vers HTTPS et au renouvellement du certificat.

Si UFW est déjà la politique de pare-feu choisie sur le serveur :

```bash
sudo apt install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 8080/tcp
sudo ufw status verbose
sudo ufw enable
```

**Attention :** adaptez la règle SSH si votre accès distant n’utilise pas le
port standard. Activez le pare-feu depuis une session SSH en gardant un accès
de secours afin d’éviter de vous verrouiller hors du serveur. Si l’accès est
réservé à un réseau privé, préférez des règles entrantes limitées aux adresses
ou sous-réseaux d’administration plutôt que d’ouvrir 80/443 à tout Internet.

Appliquez aussi ces restrictions au pare-feu du fournisseur cloud et aux règles
IPv6. N’activez pas plusieurs gestionnaires de pare-feu concurrents sans
comprendre leurs règles.

## 7. Vérifier HTTPS et le renouvellement

Depuis le serveur :

```bash
curl -I http://soc.example.com/
curl -I https://soc.example.com/
sudo certbot renew --dry-run
systemctl list-timers --all | grep -i certbot
```

La première commande doit renvoyer une redirection vers
`https://soc.example.com/`. La seconde doit répondre via HTTPS avec un code
normal (par exemple `200`). Le test Certbot doit réussir.

Depuis un autre poste, vérifiez que le dashboard fonctionne en ouvrant
`https://soc.example.com/`, que le navigateur ne signale pas d’erreur de
certificat et que la connexion API fonctionne. Vérifiez également que
`http://soc.example.com/` redirige vers HTTPS.

Confirmez enfin que le port 8080 n’est pas joignable depuis un autre poste et
que l’écoute locale reste `127.0.0.1:8080`. N’envoyez jamais un jeton API dans
une URL, une capture d’écran ou un ticket.

## Renouvellement du binaire

Après une mise à jour du code, reconstruisez et installez le binaire, puis
redémarrez le service :

```bash
go build -trimpath -o /tmp/soc-backend ./cmd/soc-backend
sudo install -o root -g root -m 0755 /tmp/soc-backend /usr/local/bin/soc-backend
rm /tmp/soc-backend
sudo systemctl restart soc-backend
sudo systemctl status soc-backend --no-pager
```

## Limites de cette configuration

Le reverse proxy chiffre le transport navigateur → Nginx. Le lien Nginx →
backend reste en HTTP, mais seulement sur la boucle locale. Si le backend et le
proxy sont sur des machines différentes, utilisez TLS ou un tunnel sécurisé
entre elles et filtrez leur trafic par pare-feu.

HTTPS ne remplace pas la rotation des secrets, les permissions strictes de la
base SQLite et des sauvegardes, les mises à jour régulières, la surveillance
des journaux ou la protection de l’accès administrateur au serveur. Consultez
aussi [SECURITY-REVIEW.md](./SECURITY-REVIEW.md) avant la mise en service.
