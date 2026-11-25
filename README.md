# Go SOC Backend

Backend SOC écrit en Go. Il collecte des alertes depuis Wazuh Indexer, les
stocke dans SQLite, les regroupe en incidents et fournit une API ainsi qu’un
dashboard web. Des analyses peuvent être réalisées par Ollama et, si IRIS est
configuré, les analyses automatiques qualifiées sont publiées dans sa timeline.

Le projet est distribué sous licence GPL-3.0 : voir [LICENSE](./LICENSE).

## Première installation sur Debian 13

Pour la première installation, utilisez `start.sh` : c’est lui qui configure
l’écoute HTTPS et peut installer le service systemd. `go run` est réservé au
développement local.

### 1. Préparer le serveur et le certificat HTTPS

Installez Go 1.24 ou plus récent et Git, puis récupérez le dépôt :

```bash
sudo apt update
sudo apt install -y git golang-go openssl python3
go version
git clone https://github.com/lb-trust/go-backend.git
cd go-backend
```

Au premier lancement, `start.sh` propose deux choix :

1. **Générer automatiquement un certificat auto-signé**. C'est le choix le
   plus simple pour démarrer : aucune demande de certificat externe n'est
   nécessaire. Le script le crée pour le nom saisi et le range dans
   `~/.config/go-backend/tls/` (`server.crt` et `server.key`). Le certificat
   est valable un an ; la clé privée est protégée et reste sur le serveur.
   C'est le choix proposé par défaut dans `start.sh` (appuyez sur Entrée).
   Les navigateurs ne font pas confiance à ce certificat par défaut et
   afficheront un avertissement. Pour une utilisation régulière depuis un
   autre poste, copiez uniquement `server.crt` vers ce poste et ajoutez-le à
   ses certificats approuvés. Ne copiez jamais `server.key`.
2. **Utiliser un certificat déjà émis**, recommandé pour un service durable
   ou accessible à plusieurs personnes. Il faut obtenir un certificat TLS
   délivré pour le nom DNS du serveur, ainsi que sa clé privée :

   - **Serveur avec un nom DNS public** : vous pouvez obtenir gratuitement un
     certificat de confiance avec Let's Encrypt. L'exemple ci-dessous utilise
     le mode autonome, qui nécessite que le DNS public pointe vers ce serveur
     et que le port 80 soit temporairement accessible et libre.

     ```bash
     sudo apt install -y certbot
     sudo certbot certonly --standalone -d soc.example.com
     ```

     Certbot place alors les fichiers sous
     `/etc/letsencrypt/live/soc.example.com/`. Remplacez `soc.example.com` par
     votre vrai nom DNS. Si le port 80 ne peut pas être utilisé, choisissez une
     autre méthode Certbot adaptée à votre réseau, par exemple la validation
     DNS.
   - **Serveur accessible uniquement sur le réseau privé** : demandez à
     l'administrateur réseau un certificat et sa clé, ou faites-les émettre
     par l'autorité de certification interne de votre organisation. Le
     certificat doit couvrir le nom DNS utilisé par les postes clients.

Pour récupérer le certificat public depuis un poste client, utilisez le chemin
affiché par `start.sh` :

```bash
scp utilisateur@serveur:/home/leo/.config/go-backend/tls/server.crt .
```

Remplacez `utilisateur@serveur` et `/home/leo` par les valeurs de votre
installation. Pour approuver le certificat sur un poste Linux, exécutez :

```bash
sudo install -m 644 server.crt /usr/local/share/ca-certificates/go-soc-backend.crt
sudo update-ca-certificates
```

Sous Windows, exécutez `certutil -user -addstore Root server.crt` pour
l'ajouter aux autorités racines de confiance de votre utilisateur. Après cette
étape, accédez au dashboard avec le même nom DNS que celui saisi à
l'installation. Si le certificat est remplacé, il faudra approuver le nouveau
certificat sur les postes concernés.

Si vous choisissez un certificat existant, rangez les fichiers hors du dépôt.
Le service tourne sous votre compte utilisateur ; la clé privée doit donc
être lisible par ce compte, mais pas par les autres. Pour l'exemple Let's
Encrypt, copiez-les dans le répertoire privé du compte qui lancera `start.sh` :

```bash
TLS_DIR="$HOME/.config/go-backend/tls"
sudo install -d -o "$USER" -g "$(id -gn)" -m 700 "$TLS_DIR"
sudo install -o "$USER" -g "$(id -gn)" -m 644 \
  /etc/letsencrypt/live/soc.example.com/fullchain.pem "$TLS_DIR/fullchain.pem"
sudo install -o "$USER" -g "$(id -gn)" -m 600 \
  /etc/letsencrypt/live/soc.example.com/privkey.pem "$TLS_DIR/privkey.pem"
```

À chaque renouvellement du certificat Let's Encrypt, mettez à jour ces deux
copies et redémarrez le service. Ne placez jamais la clé privée dans le dépôt
et ne la transmettez pas aux postes clients.

### 2. Lancer `start.sh`

Depuis la racine du dépôt, lancez le script avec votre compte normal (pas avec
`sudo`) :

```bash
chmod +x ./start.sh
./start.sh
```

Au premier lancement, le script demande le nom DNS, puis propose de générer
un certificat auto-signé ou d'utiliser un certificat existant. Si vous
choisissez le certificat auto-signé, il crée les fichiers automatiquement.
Si vous choisissez un certificat existant, indiquez ses chemins, par exemple :

```text
Nom DNS : soc.example.com
Certificat : /home/leo/.config/go-backend/tls/fullchain.pem
Clé privée : /home/leo/.config/go-backend/tls/privkey.pem
```

Il mémorise ces réponses dans `.soc-network.env`, un fichier local ignoré par
Git et protégé par des permissions privées. Il demande ensuite le nom du
service systemd (défaut : `go-soc-backend`) et propose de l'installer et de le
démarrer. Répondez oui pour un démarrage automatique après redémarrage ; `sudo`
est alors utilisé uniquement pour installer le service. Le dépôt doit être
dans un chemin sans espaces. Si vous refusez l'installation, le backend reste
lancé au premier plan dans le terminal.

Le script demande aussi l'adresse IP autorisée à créer le premier compte
administrateur. Saisissez l'IP publique ou privée depuis laquelle vous ouvrirez
le navigateur ; cette IP exacte s'ajoute à l'accès local déjà autorisé.
Entrée laisse la création réservée au serveur local, et `-` supprime une
autorisation distante précédemment enregistrée. Cette règle ne concerne que
la création initiale, qui ne peut réussir qu'une fois. L'accès distant doit se
faire directement vers le serveur en HTTPS, et le pare-feu doit lui aussi
autoriser uniquement les adresses nécessaires. Si vous passez par un proxy,
l'application voit l'adresse du proxy et non celle de votre poste.

Après le démarrage, ouvrez `https://soc.example.com:8080/`. Le nom DNS doit
pointer vers le serveur et le pare-feu doit autoriser le port 8080 uniquement
depuis le réseau de confiance. Le nom du service est un identifiant systemd,
pas une commande à saisir seule. Par exemple, si vous avez choisi `go-soc`,
utilisez ces commandes pour le gérer :

```bash
sudo systemctl status go-soc.service
sudo journalctl -u go-soc.service -f
sudo systemctl restart go-soc.service
sudo systemctl stop go-soc.service
```

Remplacez `go-soc` par le nom choisi pendant l'installation.

### Modifier la configuration après l'installation

Pour relancer l'assistant, connectez-vous au serveur avec le compte qui a
installé le service, placez-vous dans le dépôt et exécutez de nouveau :

```bash
cd ~/go-backend
./start.sh
```

Quand une configuration existe, choisissez **1** pour la conserver ou **2**
pour la modifier. Le mode modification permet de changer le DNS, le certificat
et l'IP autorisée à créer le premier compte ; le service existant est ensuite
redémarré. Cela ne supprime pas la base SQLite, les comptes admin ni la
configuration Wazuh qui y est enregistrée. Si vous choisissez de conserver la
configuration, le script démarre le service existant sans la remplacer.

Lors de la première visite, créez le compte administrateur ; les aides « i »
expliquent les règles de saisie. Le mot de passe doit contenir au moins
12 caractères. Sur une base déjà configurée, la page de connexion s'affiche.
Depuis **Configuration**, ouvrez **Configuration Wazuh** pour saisir l'URL de
l'Indexer, le compte en lecture seule et son mot de passe. La connexion est
testée avant l'enregistrement dans SQLite et la collecte démarre sans
redémarrage. `start.sh` crée automatiquement la clé locale nécessaire au
chiffrement du mot de passe ; aucune case ni clé à saisir dans l'interface
n'est nécessaire. Chaque champ Wazuh comporte une aide « i » avec des exemples.

Les groupes d'agents sont découverts à partir des alertes et affichés en ordre
alphabétique dans les filtres du dashboard.

L’interface configure une seule connexion Wazuh Indexer. Les groupes viennent
des alertes de cette source : ils ne nécessitent pas de configuration séparée.

Pour modifier un mot de passe, fournissez l’ancien, puis saisissez deux fois
le nouveau (12 caractères minimum). La session web expire après 8 heures et est
réinitialisée au redémarrage du service. Le changement de mot de passe révoque
toutes les sessions et demande une nouvelle connexion. La gestion disponible
pour le moment concerne les comptes administrateurs.

Les comptes et réglages restent dans la base SQLite locale. Par défaut, elle
s’appelle `soc.db` dans le répertoire courant et n’est pas versionnée par Git.
Pour que son emplacement reste stable, créez un répertoire hors du dépôt :

```bash
mkdir -p "$HOME/.local/share/go-backend"
chmod 700 "$HOME/.local/share/go-backend"
```

Pour le service systemd créé par `start.sh`, ajoutez dans `.soc-service.env`
(à la racine du dépôt) une ligne avec le chemin absolu :

```text
SOC_DB_PATH=/home/leo/.local/share/go-backend/soc.db
```

Le service charge ce fichier au démarrage ; protégez-le avec `chmod 600`.
Le compte exécutant le service doit pouvoir écrire dans le répertoire de la
base. Les mots de passe des comptes sont hachés ; le mot de passe Wazuh est
chiffré avec une clé externe configurée par `SOC_CREDENTIAL_KEY_FILE`.
Protégez la base et la clé. Le compte initial n’a plus de mot de passe public
par défaut. Si une ancienne base contient encore le compte `admin` avec le
mot de passe `admin`, le tableau de bord impose la configuration du nouveau
compte avant d’autoriser la connexion.

#### Mise à jour depuis une version qui suivait `cmd/soc-backend/soc.db`

Si `git pull` refuse la mise à jour parce que `cmd/soc-backend/soc.db` a été
modifiée localement, arrêtez d’abord le backend. Sauvegardez la base hors du
dépôt, puis restaurez uniquement la copie suivie par Git afin de permettre la
mise à jour :

```bash
set -e
mkdir -p "$HOME/.local/share/go-backend"
DB_PATH="$HOME/.local/share/go-backend/soc.db"
if [ -e "$DB_PATH" ]; then
  echo "La base de destination existe déjà ; choisissez un autre chemin."
else
  cp -a cmd/soc-backend/soc.db "$DB_PATH"
  git restore -- cmd/soc-backend/soc.db
  git pull
  export SOC_DB_PATH="$DB_PATH"
fi
```

Après cette migration, ajoutez `SOC_DB_PATH=/home/leo/.local/share/go-backend/soc.db`
dans `.soc-service.env`, puis redémarrez le service. La base continue ainsi
d’être utilisée localement, tandis que les mises à jour Git ne la remplacent
plus.

La connexion par jeton API reste disponible pour les intégrations et
l’ingestion d’alertes ; elle n’est plus nécessaire pour ouvrir le dashboard.

## Configuration Wazuh avancée (facultative)

Le backend interroge **Wazuh Indexer** en lecture seule. Il doit pouvoir joindre
son URL et utiliser un compte ayant accès en lecture à l’index d’alertes. Il ne
se connecte pas directement à l’agent ni au manager Wazuh. La méthode
recommandée est de terminer la première installation avec `start.sh`, créer le
compte administrateur, puis renseigner l’Indexer dans **Configuration >
Configuration Wazuh**. Il n’est pas nécessaire de préparer des variables
d’environnement pour un démarrage normal.

Les anciennes installations peuvent encore utiliser `WAZUH_SOURCES_JSON` pour
fournir la configuration Wazuh au démarrage. Pour le service systemd créé par
`start.sh`, les variables persistantes doivent être définies dans
`.soc-service.env` à la racine du dépôt. Ce fichier peut contenir des secrets :
ne le versionnez jamais et limitez ses permissions à son propriétaire
(`chmod 600 .soc-service.env`).

### Lancement local de développement sous Windows (PowerShell)

Depuis la racine du dépôt, exécutez ce bloc dans le même terminal. Remplacez
`https://INDEXER:9200` par l’URL joignable de votre Wazuh Indexer. La demande
d’identifiants PowerShell évite d’inscrire le mot de passe dans la commande.

```powershell
$credential = Get-Credential -UserName "soc-reader" -Message "Compte Wazuh Indexer en lecture seule"
$source = @{ tenant_id = "client-a"; url = "https://INDEXER:9200"; username = $credential.UserName; password = $credential.GetNetworkCredential().Password; verify_tls = $true; alerts_index = "wazuh-alerts-*"; batch_size = 100 }
$env:WAZUH_SOURCES_JSON = ConvertTo-Json -InputObject @($source) -Compress
go run .\cmd\soc-backend
```

Le serveur démarre alors la collecte automatiquement, toutes les 60 secondes
par défaut. Gardez cette fenêtre ouverte : la configuration définie avec
`$env:` s’applique au processus lancé depuis ce terminal. Ce mode est destiné
au développement local ; pour une première installation Debian ou un service
accessible sur le réseau, suivez plutôt la procédure `start.sh` en haut de ce
README.

Après le démarrage, ouvrez `http://127.0.0.1:8080/` et connectez-vous avec le
compte administrateur. Aucun jeton API n’est généré pour le dashboard ; les
intégrations API peuvent en configurer un explicitement avec
`SOC_TENANTS_JSON`.

### Vérifier la connexion et les alertes

Cliquez sur l’indicateur **Wazuh** en haut du dashboard pour ouvrir la page de
maintenance. Elle donne, pour chaque source :

- le résultat du dernier contrôle de l’Indexer et l’heure du contrôle ;
- la date du dernier contrôle réussi ;
- le nombre d’alertes lues lors de ce contrôle ;
- l’heure de la dernière alerte Wazuh, si une alerte a été reçue ;
- le message d’erreur, le cas échéant ;
- l’espace utilisé par le fichier SQLite et ses fichiers WAL/SHM.

« Aucune source Wazuh configurée » signifie qu’aucune connexion n’a été
enregistrée. Ouvrez **Configuration > Configuration Wazuh** pour renseigner ou
corriger les paramètres ; la modification est testée et appliquée sans
redémarrage.

« Connexion OK, aucune alerte récente » signifie que l’Indexer répond, mais
qu’aucune nouvelle alerte n’a été lue récemment. Une source configurée mais en
erreur indique plutôt un souci d’URL, d’identifiants, de droits d’index, de
certificat TLS ou de réseau.

La collecte utilise la date `timestamp` des documents et l’index
`wazuh-alerts-*` par défaut. Les alertes continuent d’être interrogées même si
aucune nouvelle alerte n’est produite : la page permet ainsi de distinguer une
connexion valide d’une absence de nouvelles alertes.

## Arborescence du projet

```text
go-backend/
├── cmd/
│   └── soc-backend/
│       └── main.go              # Démarrage serveur, collecteurs et worker IA
├── internal/
│   └── soc/
│       ├── auth.go               # Comptes, sessions et configuration Wazuh
│       ├── backend.go           # SQLite, ingestion, regroupement, incidents
│       ├── backend_test.go      # Tests backend, API et collecte Wazuh
│       ├── clients.go           # Clients Ollama, Wazuh et IRIS
│       ├── config.go            # Configuration et validation des variables
│       ├── config_test.go       # Tests de configuration
│       ├── control.go           # File IA et contrôle de l’analyse
│       ├── server.go            # Routes HTTP et authentification
│       ├── web.go               # Intégration des pages web dans le binaire
│       └── web/
│           ├── dashboard.css    # Styles partagés des pages
│           ├── dashboard.js     # Dashboard, filtres et indicateur Wazuh
│           ├── index.html       # Page principale SOC
│           ├── maintenance.html # Diagnostic de la collecte Wazuh
│           ├── maintenance.js  # Affichage du diagnostic Wazuh
│           ├── accounts.html   # Gestion des comptes administrateurs
│           ├── settings.html   # Configuration graphique Wazuh
│           └── admin.js        # Interactions des pages d’administration
├── other/
│   └── alert.json              # Exemple d’alerte Wazuh (groupe ClientB)
├── LICENSE
├── go.mod
├── go.sum
├── Lien_wazuh_backend.md       # Notes d’intégration Wazuh
└── README.md
```

`soc.db` est créé au démarrage selon la configuration ; c’est un fichier local
d’exécution, pas une source du projet.

## Fonctionnalités

- Dashboard avec comptes administrateurs persistés dans SQLite et API HTTP JSON
  authentifiée par jeton pour les intégrations ; les données sont isolées par
  client (`tenant_id`).
- Configuration Wazuh testée et enregistrée depuis l’interface ; les filtres de
  groupes du dashboard sont découverts automatiquement.
- Recherche d’inventaire par ID, IP ou nom d’agent, présentant les logiciels
  concernés dans l’ordre de priorité sans afficher les détails des CVE.
- Collecte périodique optionnelle du Wazuh Indexer en lecture seule et
  ingestion manuelle d’alertes.
- Déduplication des identifiants Wazuh, regroupement par client, règle et
  agent, avec calcul des occurrences, IP sources, score et sévérité.
- Filtre de groupes Wazuh dans le dashboard basé sur
  `agent.labels.group` (par exemple `ClientA` et `ClientB`). Ce label de groupe
  est distinct du `tenant_id`, qui détermine l’isolation des données.
- Corrélation des incidents et file persistante d’analyse IA.
- Analyse automatique ou manuelle avec Ollama.
- Publication optionnelle des analyses automatiques qualifiées vers IRIS DFIR.
- Dashboard intégré et page de maintenance Wazuh, sans dépendance JavaScript
  externe ; la maintenance affiche aussi l’espace utilisé par SQLite, WAL et
  SHM.
- Détail d’incident accessible en cliquant sur sa ligne : alertes liées,
  résumé IA, changement de statut, commentaires et suppression avec confirmation.

## Configuration

| Variable | Défaut | Description |
| --- | --- | --- |
| `WAZUH_SOURCES_JSON` | `[]` | Configuration de démarrage par environnement, utilisée si SQLite ne contient pas déjà de paramètres Wazuh. |
| `WAZUH_POLL_SECONDS` | `60` | Période entre les contrôles ; minimum 15 secondes. |
| `SOC_TENANTS_JSON` | tenant `client-a`, sans jeton API | Objet JSON facultatif `jeton: tenant_id` pour les intégrations qui appellent l’API. |
| `SOC_DB_PATH` | `soc.db` | Chemin de la base SQLite. |
| `SOC_CREDENTIAL_KEY_FILE` | généré par `start.sh` | Fichier de clé aléatoire de 32 octets utilisé pour chiffrer le mot de passe Wazuh. En lancement manuel du binaire, fournissez vous-même ce chemin. |
| `SOC_SETUP_ALLOWED_IP` | vide | Adresse IPv4 ou IPv6 exacte autorisée en plus de la connexion locale à créer le premier compte admin ; par défaut, seule une connexion locale est autorisée. |
| `SOC_HOST` / `SOC_PORT` | `127.0.0.1` / `8080` | Adresse et port du serveur HTTP. `go run` écoute localement ; `start.sh` configure `0.0.0.0` en HTTPS pour l’accès réseau. |
| `SOC_TLS_CERT_FILE` / `SOC_TLS_KEY_FILE` | non définis | Certificat et clé PEM ; obligatoires ensemble pour écouter sur une adresse non locale. |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Origine de l’API Ollama. |
| `OLLAMA_MODEL` | `llama3.1` | Modèle utilisé pour l’analyse. |
| `IRIS_BASE_URL` | désactivé | Origine HTTPS IRIS, sans chemin final. |
| `IRIS_API_KEY` | désactivé | Clé API IRIS. |
| `IRIS_CASE_ID` | désactivé | Identifiant numérique du cas IRIS cible. |

Pour les déploiements qui utilisent encore `WAZUH_SOURCES_JSON`, chaque entrée
contient :

| Champ | Obligatoire | Signification |
| --- | --- | --- |
| `tenant_id` | oui | Client auquel rattacher les alertes ; sans configuration API explicite, utilisez `client-a`. |
| `url` | oui | Origine de Wazuh Indexer, par exemple `https://indexer.example.lan:9200`. |
| `username`, `password` | oui | Compte Indexer en lecture seule. |
| `verify_tls` | non | `true` par défaut ; conserve la vérification des certificats TLS. |
| `alerts_index` | non | Index à lire ; `wazuh-alerts-*` par défaut. |
| `vulnerabilities_index` | non | Index d’inventaire à consulter ; `wazuh-states-vulnerabilities-*` par défaut. |
| `batch_size` | non | Nombre maximal de résultats par contrôle ; `100` par défaut, maximum `1000`. |

L’écran « Versions à mettre à jour » recherche les détections présentes dans
l’inventaire Wazuh courant à partir de l’ID d’un agent. Les logiciels sont
regroupés par nom et version, puis triés selon leur priorité de sévérité ; cet
écran ne remplace pas la vérification des mises à jour disponibles chez les
éditeurs.

`tenant_id` est un paramètre interne de l’ancienne configuration par
environnement ; il n’est pas demandé dans l’interface graphique. Dans le
dashboard, les groupes tels que `ClientA` et `ClientB` proviennent des labels
Wazuh et sont filtrables indépendamment.

IRIS est désactivé par défaut. Pour l’activer, fournissez ensemble
`IRIS_BASE_URL`, `IRIS_API_KEY` et `IRIS_CASE_ID`. Ne mettez jamais de mot de
passe ou de clé dans le dépôt. `verify_tls: false` est réservé aux essais
locaux avec un certificat non approuvé.

## Accès réseau et sécurité

Par défaut, le serveur écoute sur `127.0.0.1:8080` ; seul le serveur local peut
accéder directement au dashboard. `start.sh` permet d'autoriser une IP précise
à créer le premier compte administrateur à distance. Cette autorisation est
limitée à cette création initiale ; elle n'accorde pas de compte ni d'accès
administrateur par elle-même. L'adresse est comparée à l'adresse réseau réelle
de la connexion, sans faire confiance aux en-têtes proxy. Lorsqu'un proxy
inverse est utilisé, le backend voit l'adresse du proxy. Pour une exposition
distante, utilisez `./start.sh` avec un certificat TLS couvrant le nom DNS du
serveur. Le script écoute sur toutes les interfaces réseau. Une écoute distante
est refusée sans certificat et clé TLS configurés. Limitez aussi les sources
autorisées avec un pare-feu.

Le serveur utilise HTTP pour l’écoute locale par défaut. Toute écoute sur une
adresse non locale utilise TLS avec `SOC_TLS_CERT_FILE` et `SOC_TLS_KEY_FILE`.
Utilisez un compte Wazuh en lecture seule. Son mot de passe est chiffré dans
SQLite avec AES-GCM. Quand vous lancez le service avec `start.sh`, le script
crée automatiquement la clé aléatoire de 32 octets dans
`~/.config/go-backend/wazuh.key`, avec des permissions privées, puis la
réutilise à chaque démarrage. Vous n'avez rien à saisir dans l'interface
Wazuh pour cette clé.

Sauvegardez ce fichier séparément de la base et protégez sa copie : sans la clé,
le backend ne peut pas déchiffrer les identifiants Wazuh. Ne la supprimez pas
et ne la mettez pas dans le dépôt. Les anciens mots de passe en clair sont
chiffrés automatiquement au démarrage lorsque la clé est disponible ; protégez
ou supprimez aussi les anciennes sauvegardes qui peuvent encore les contenir.
Pour un lancement manuel du binaire sans `start.sh`, il faut fournir un fichier
de clé et définir `SOC_CREDENTIAL_KEY_FILE`. Pour IRIS, gardez la clé API dans
l'environnement ou un gestionnaire de secrets, jamais dans le dépôt.

Pour un exemple détaillé de déploiement avec Nginx et TLS sur Debian 13, voir
[SECURISER-HTTP-DEBIAN-13.md](./SECURISER-HTTP-DEBIAN-13.md).

## API

Les intégrations continuent d’utiliser
`Authorization: Bearer <jeton API>`. Le dashboard utilise un jeton de session
obtenu à la connexion, conservé en mémoire par le serveur et invalidé à son
redémarrage. Les jetons d’intégration servent à ingérer des alertes et à
consulter les données autorisées ; les modifications d’incidents, le contrôle
IA et les routes `/api/admin/...` nécessitent une session administrateur.

| Méthode et route | Usage |
| --- | --- |
| `GET /health` | Santé du service, sans authentification. |
| `GET /api/setup/status` | Indique si la création initiale du compte administrateur est nécessaire. |
| `POST /api/setup/admin` | Créer le premier compte admin ou remplacer l’ancien compte par défaut ; utilisable une seule fois. |
| `POST /api/auth/login` | Connexion par identifiant et mot de passe ; retourne une session. |
| `POST /api/auth/logout` | Révoquer la session courante. |
| `GET /api/auth/me` | Compte associé à la session. |
| `GET /api/admin/accounts` | Lister les comptes administrateurs. |
| `POST /api/admin/accounts` | Créer un compte administrateur. |
| `DELETE /api/admin/accounts/{username}` | Supprimer un autre compte administrateur ; le dernier compte ne peut pas être supprimé. |
| `PATCH /api/admin/password` | Modifier son mot de passe avec l’ancien et deux saisies identiques du nouveau. |
| `GET /api/admin/wazuh` | Lire les paramètres Wazuh sans divulguer le mot de passe. |
| `PUT /api/admin/wazuh` | Tester et enregistrer la connexion Wazuh. |
| `DELETE /api/admin/wazuh` | Supprimer la configuration Wazuh. |
| `GET /api/dashboard` | Compteurs et sévérités du client. |
| `GET /api/clients` | Groupes Wazuh présents pour le client du jeton connecté. |
| `GET /api/wazuh/status` | État des sources Wazuh du client, erreurs éventuelles et taille des fichiers SQLite. |
| `GET /api/control/ai` | État de la file IA et 100 derniers traitements. |
| `PATCH /api/control/ai` | Pause/reprise globale, corps `{"enabled":false}` ou `{"enabled":true}`. |
| `GET /api/alerts?limit=100&since=...` | Groupes d’alertes récents ; `since` est une date RFC3339. |
| `POST /api/alerts` | Ingestion manuelle d’une alerte JSON Wazuh. |
| `GET /api/incidents` | Liste paginée ; filtres facultatifs `status`, `severity`, `min_level`, `q`, `from`, `to` et `group`. `limit` est plafonné à 500, `offset` parcourt les pages. La réponse contient `items`, `total`, `offset`, `limit` et `has_more`. |
| `GET /api/incidents/{id}` | Incident, alertes liées et feedback. |
| `PATCH /api/incidents/{id}` | Modification de `status` et/ou ajout de `feedback`. |
| `DELETE /api/incidents/{id}` | Supprimer l’incident, ses commentaires, son analyse et son traitement IA ; les alertes sources sont conservées. Refusé pendant une analyse en cours. |
| `POST /api/incidents/{id}/analyze` | Analyse manuelle avec Ollama. |
| `POST /api/incidents/{id}/queue` | Forcer une nouvelle analyse via la file persistante. |
| `DELETE /api/incidents/{id}/queue` | Retirer de la file un traitement en attente ou en échec. |

Pour filtrer les incidents par groupes, ajouter `group_filter=true` et un ou
plusieurs paramètres `group`. `q` recherche dans le titre et les informations
de l’agent ; `from` et `to` sont des dates de création inclusives au format
`AAAA-MM-JJ`.

## Traitement des alertes et de l’IA

Les alertes de niveau Wazuh inférieur à 10 sont regroupées par règle et agent
sur six heures, mais ne sont rattachées à un incident qu’à partir de 10
occurrences dans ce groupe. À partir du niveau 10, elles sont rattachées
immédiatement et regroupées sur 30 minutes. Les incidents ouverts ou en cours
peuvent être corrélés pendant 30 minutes après leur dernière mise à jour.
L’analyse automatique démarre après 40 occurrences d’alertes faibles ou
immédiatement à partir du niveau Wazuh 10. Les tentatives échouées sont
réessayées jusqu’à trois fois.

La pause IA est globale et persistante ; elle n’interrompt pas la collecte
Wazuh. Une analyse déjà démarrée peut se terminer. « Forcer l’analyse » remet
l’incident en file, même s’il a déjà été analysé.

## Développement et tests

Go 1.24 ou plus récent est nécessaire.

```powershell
go test ./...
go vet ./...
```
