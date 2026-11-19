# Go SOC Backend

Backend SOC écrit en Go. Il collecte des alertes depuis Wazuh Indexer, les
stocke dans SQLite, les regroupe en incidents et fournit une API ainsi qu’un
dashboard web. Des analyses peuvent être réalisées par Ollama et, si IRIS est
configuré, les analyses automatiques qualifiées sont publiées dans sa timeline.

Le projet est distribué sous licence GPL-3.0 : voir [LICENSE](./LICENSE).

## Premier démarrage et configuration graphique

Lancez le service depuis la racine du dépôt :

```bash
go run ./cmd/soc-backend
```

Ouvrez `http://127.0.0.1:8080/`. Lors du premier lancement, la page demande
l’identifiant et le mot de passe du compte administrateur initial ; des aides
« i » expliquent les règles de saisie. Le mot de passe doit contenir au moins
12 caractères. Sur une base existante déjà configurée, la page de connexion
reste affichée. Depuis **Configuration**, gérez ensuite les comptes ou ouvrez
**Configuration Wazuh** pour saisir l’URL de l’Indexer, le compte en lecture
seule et son mot de passe. Le service teste la connexion avant d’enregistrer
les réglages dans SQLite ; la collecte démarre sans redémarrage.
Configurez auparavant le fichier de clé `SOC_CREDENTIAL_KEY_FILE` décrit dans
la section **Accès réseau et sécurité**.
Si le certificat TLS de l’Indexer n’est pas reconnu, l’option **Ignorer les
erreurs du certificat TLS** permet de tester la connexion, mais réduit sa
sécurité. Préférez installer l’autorité de certification appropriée.
Chaque champ de configuration Wazuh comporte une aide « i » avec des exemples
et des commandes pour retrouver ou vérifier la valeur.
Les groupes d’agents sont découverts à partir des alertes et affichés en ordre
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
Pour que son emplacement reste stable, configurez de préférence un chemin absolu
hors du dépôt, par exemple :

```bash
mkdir -p "$HOME/.local/share/go-backend"
export SOC_DB_PATH="$HOME/.local/share/go-backend/soc.db"
```

Définissez `SOC_DB_PATH` de la même façon dans l’environnement du service
`systemd` pour qu’il retrouve la base après chaque redémarrage. Le compte
exécutant le service doit pouvoir écrire dans le répertoire. Les mots de passe
des comptes sont hachés ; le mot de passe Wazuh est chiffré avec une clé externe
configurée par `SOC_CREDENTIAL_KEY_FILE`. Protégez la base et la clé. Le compte
initial n’a plus de mot de passe public par défaut. Si une ancienne base
contient encore le compte `admin` avec le mot de passe `admin`, le tableau de
bord impose la configuration du nouveau compte avant d’autoriser la connexion.

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

Lancez ensuite le backend avec cette variable, et configurez-la également dans
`systemd` si le service démarre automatiquement. La base continue ainsi d’être
utilisée localement, tandis que les mises à jour Git ne la remplacent plus.

La connexion par jeton API reste disponible pour les intégrations et
l’ingestion d’alertes ; elle n’est plus nécessaire pour ouvrir le dashboard.

## Configuration manuelle (optionnelle)

Le backend interroge **Wazuh Indexer** en lecture seule. Il doit pouvoir joindre
son URL et utiliser un compte ayant accès en lecture à l’index d’alertes. Il ne
se connecte pas directement à l’agent ni au manager Wazuh. Cette méthode par
variables d’environnement est une alternative au formulaire graphique ; une
configuration déjà enregistrée dans SQLite reste prioritaire au redémarrage.

### Debian (recommandé)

Le projet nécessite Go 1.24 ou plus récent. Debian 13 est recommandé ; sur
Debian 12, vérifiez que la version de Go installée est au moins 1.24 avec
`go version`. Si ce n’est pas le cas, installez une version récente de Go avant
de continuer.

Installez les outils nécessaires et récupérez le dépôt :

```bash
sudo apt update && sudo apt install -y git golang-go python3 ca-certificates
git clone https://github.com/lb-trust/go-backend.git && cd go-backend
```

Depuis la racine du dépôt, renseignez l’URL, le compte Indexer en lecture seule
et son mot de passe. Le mot de passe est demandé sans être affiché ni inscrit
dans l’historique de commandes. Adaptez `client-a` si votre jeton utilise un
autre `tenant_id` :

```bash
read -r -p "URL Wazuh Indexer (ex. https://indexer.example.lan:9200) : " WAZUH_URL
read -r -p "Utilisateur Indexer : " WAZUH_USER
read -r -s -p "Mot de passe Indexer : " WAZUH_PASSWORD; printf '\n'
export WAZUH_URL WAZUH_USER WAZUH_PASSWORD
export WAZUH_SOURCES_JSON="$(python3 -c 'import json,os; print(json.dumps([{"tenant_id":"client-a","url":os.environ["WAZUH_URL"],"username":os.environ["WAZUH_USER"],"password":os.environ["WAZUH_PASSWORD"],"verify_tls":True,"alerts_index":"wazuh-alerts-*","batch_size":100}]))')"
chmod +x ./start.sh
./start.sh
```

Le script `start.sh` lance le backend avec `go run`. Il attend que Go soit
disponible à `/usr/bin/go` et que le dépôt se trouve dans `/backend/go-backend`,
chemin défini par sa commande `cd`. Si le dépôt se trouve ailleurs, modifiez
cette ligne dans `start.sh` pour indiquer son chemin réel.

Configurez Wazuh et les autres options en exportant leurs variables dans le
même terminal **avant** de lancer `./start.sh` : le script les transmet au
backend. Les variables de l’exemple ci-dessus ne durent que pendant la session
du terminal. Pour un lancement permanent, définissez-les dans le service
`systemd` qui lance le script ou dans son fichier d’environnement, lisible
uniquement par l’utilisateur du service. N’inscrivez pas les mots de passe ni
les clés dans `start.sh` ou dans le dépôt.

Laissez le terminal ouvert : le backend collecte automatiquement les alertes
toutes les 60 secondes.

### Windows (PowerShell)

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
`$env:` s’applique au processus lancé depuis ce terminal. Pour un lancement
automatique après redémarrage, fournissez les variables d’environnement au
service ou au script qui démarre le backend.

Après le démarrage, ouvrez `http://127.0.0.1:8080/` et utilisez le compte
administrateur. Le jeton API généré reste réservé aux intégrations ; son chemin
est indiqué dans les journaux et sa valeur est conservée dans le fichier local
configuré par `SOC_API_TOKEN_FILE`.

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

`soc.db` et `.soc-api-token` sont créés au démarrage selon la configuration ;
ce sont des fichiers locaux d’exécution, pas des sources du projet.

## Fonctionnalités

- Dashboard avec comptes administrateurs persistés dans SQLite et API HTTP JSON
  authentifiée par jeton pour les intégrations ; les données sont isolées par
  client (`tenant_id`).
- Configuration Wazuh testée et enregistrée depuis l’interface ; les filtres de
  groupes du dashboard sont découverts automatiquement.
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
| `SOC_TENANTS_JSON` | client `client-a` généré | Objet JSON `jeton: tenant_id` pour configurer explicitement les clients et jetons. |
| `SOC_API_TOKEN_FILE` | `.soc-api-token` | Fichier local contenant le jeton généré automatiquement. |
| `SOC_DB_PATH` | `soc.db` | Chemin de la base SQLite. |
| `SOC_CREDENTIAL_KEY_FILE` | non défini | Fichier contenant la clé aléatoire de 32 octets qui chiffre le mot de passe Wazuh ; protège le fichier par des permissions réservées au compte du service. |
| `SOC_HOST` / `SOC_PORT` | `127.0.0.1` / `8080` | Adresse et port du serveur HTTP. L’écoute est limitée à la machine par défaut. |
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
| `tenant_id` | oui | Client auquel rattacher les alertes ; doit correspondre à un client configuré. Avec le jeton généré par défaut, utilisez `client-a`. |
| `url` | oui | Origine de Wazuh Indexer, par exemple `https://indexer.example.lan:9200`. |
| `username`, `password` | oui | Compte Indexer en lecture seule. |
| `verify_tls` | non | `true` par défaut ; conserve la vérification des certificats TLS. |
| `alerts_index` | non | Index à lire ; `wazuh-alerts-*` par défaut. |
| `batch_size` | non | Nombre maximal de résultats par contrôle ; `100` par défaut, maximum `1000`. |

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
accéder directement au dashboard. Effectuez la configuration initiale avant
d’exposer le dashboard, par exemple depuis le serveur ou au moyen d’un tunnel
SSH. La création initiale du compte est limitée aux connexions locales. Un
reverse proxy exécuté sur le serveur est vu comme local par le backend : ne
l’exposez qu’après la création du compte. Pour une exposition distante,
utilisez de préférence un reverse proxy HTTPS local. Une écoute sur une
adresse non locale est refusée sans certificat et clé TLS configurés. Limitez
aussi les sources autorisées avec un pare-feu.

Le serveur utilise HTTP pour l’écoute locale par défaut. Toute écoute sur une
adresse non locale utilise TLS avec `SOC_TLS_CERT_FILE` et `SOC_TLS_KEY_FILE`.
Utilisez un compte Wazuh en lecture seule. Son mot de passe est chiffré dans
SQLite avec AES-GCM ; `SOC_CREDENTIAL_KEY_FILE` doit désigner un fichier
contenant exactement 32 octets aléatoires, lisible uniquement par le compte du
service. Par exemple, créez la clé sous un compte qui peut ensuite la rendre
accessible au service :

```bash
umask 077
mkdir -p "$HOME/.config/go-backend"
chmod 700 "$HOME/.config/go-backend"
openssl rand -out "$HOME/.config/go-backend/wazuh.key" 32
chmod 600 "$HOME/.config/go-backend/wazuh.key"
export SOC_CREDENTIAL_KEY_FILE="$HOME/.config/go-backend/wazuh.key"
```

Exécutez ces commandes avec le compte du service, ou donnez-lui ensuite la
propriété du fichier et du répertoire. Définissez également ce chemin dans
l’environnement `systemd`. Sauvegardez la clé séparément de la base : sans
elle, le backend ne peut pas déchiffrer les identifiants Wazuh et refuse de
démarrer. Les anciens mots de passe en clair sont chiffrés automatiquement au
démarrage lorsque la clé est configurée ; protégez ou supprimez aussi les
anciennes sauvegardes qui peuvent encore contenir ces mots de passe. Pour IRIS,
gardez la clé API dans l’environnement ou un
gestionnaire de secrets, jamais dans le dépôt.

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
| `GET /api/incidents?status=open&limit=100` | Liste d’incidents ; statut facultatif. |
| `GET /api/incidents/{id}` | Incident, alertes liées et feedback. |
| `PATCH /api/incidents/{id}` | Modification de `status` et/ou ajout de `feedback`. |
| `DELETE /api/incidents/{id}` | Supprimer l’incident, ses commentaires, son analyse et son traitement IA ; les alertes sources sont conservées. Refusé pendant une analyse en cours. |
| `POST /api/incidents/{id}/analyze` | Analyse manuelle avec Ollama. |
| `POST /api/incidents/{id}/queue` | Forcer une nouvelle analyse via la file persistante. |
| `DELETE /api/incidents/{id}/queue` | Retirer de la file un traitement en attente ou en échec. |

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
