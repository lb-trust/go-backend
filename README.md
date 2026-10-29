# Go SOC Backend

Backend SOC écrit en Go. Il collecte des alertes depuis Wazuh Indexer, les
stocke dans SQLite, les regroupe en incidents et fournit une API ainsi qu’un
dashboard web. Des analyses peuvent être réalisées par Ollama et, si IRIS est
configuré, les analyses automatiques qualifiées sont publiées dans sa timeline.

Le projet est distribué sous licence GPL-3.0 : voir [LICENSE](./LICENSE).

## Relier le backend à Wazuh

Le backend interroge **Wazuh Indexer** en lecture seule. Il doit pouvoir joindre
son URL et utiliser un compte ayant accès en lecture à l’index d’alertes. Il ne
se connecte pas directement à l’agent ni au manager Wazuh.

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
go run ./cmd/soc-backend
```

Laissez le terminal ouvert : le backend collecte automatiquement les alertes
toutes les 60 secondes. Les variables définies par `export` ne s’appliquent
qu’à cette session shell. Pour un lancement permanent après redémarrage,
définissez ces variables dans le service `systemd` qui lance le backend, ou
utilisez un fichier d’environnement lisible uniquement par l’utilisateur du
service. N’inscrivez pas le mot de passe dans le dépôt.

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

Après le démarrage du backend, ouvrez `http://127.0.0.1:8080/`. Au premier
démarrage, le backend crée et affiche un jeton API pour `client-a`; entrez-le
dans le dashboard.
Le jeton est conservé dans `.soc-api-token`. Ne le partagez pas.

### Vérifier la connexion et les alertes

Cliquez sur l’indicateur **Wazuh** en haut du dashboard pour ouvrir la page de
maintenance. Elle donne, pour chaque source :

- le résultat du dernier contrôle de l’Indexer et l’heure du contrôle ;
- la date du dernier contrôle réussi ;
- le nombre d’alertes lues lors de ce contrôle ;
- l’heure de la dernière alerte Wazuh, si une alerte a été reçue ;
- le message d’erreur, le cas échéant.

« Aucune source Wazuh configurée » signifie que le processus backend n’a pas
reçu de source pour le client lié au jeton. Vérifiez la variable
`WAZUH_SOURCES_JSON` dans le terminal ou le service qui **lance** le backend,
puis redémarrez-le après correction.

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
│           └── maintenance.js  # Affichage du diagnostic Wazuh
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

- API HTTP JSON authentifiée par jeton ; les données sont isolées par client
  (`tenant_id`).
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
  externe.

## Configuration

| Variable | Défaut | Description |
| --- | --- | --- |
| `WAZUH_SOURCES_JSON` | `[]` | Tableau JSON des sources Wazuh Indexer. Voir l’exemple de démarrage ci-dessus. |
| `WAZUH_POLL_SECONDS` | `60` | Période entre les contrôles ; minimum 15 secondes. |
| `SOC_TENANTS_JSON` | client `client-a` généré | Objet JSON `jeton: tenant_id` pour configurer explicitement les clients et jetons. |
| `SOC_API_TOKEN_FILE` | `.soc-api-token` | Fichier local contenant le jeton généré automatiquement. |
| `SOC_DB_PATH` | `soc.db` | Chemin de la base SQLite. |
| `SOC_HOST` / `SOC_PORT` | `0.0.0.0` / `8080` | Adresse et port du serveur HTTP. Utilisez `127.0.0.1` pour limiter l’accès à la machine. |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Origine de l’API Ollama. |
| `OLLAMA_MODEL` | `llama3.1` | Modèle utilisé pour l’analyse. |
| `IRIS_BASE_URL` | désactivé | Origine HTTPS IRIS, sans chemin final. |
| `IRIS_API_KEY` | désactivé | Clé API IRIS. |
| `IRIS_CASE_ID` | désactivé | Identifiant numérique du cas IRIS cible. |

Une entrée `WAZUH_SOURCES_JSON` contient :

| Champ | Obligatoire | Signification |
| --- | --- | --- |
| `tenant_id` | oui | Client auquel rattacher les alertes ; doit correspondre à un client configuré. Avec le jeton généré par défaut, utilisez `client-a`. |
| `url` | oui | Origine de Wazuh Indexer, par exemple `https://indexer.example.lan:9200`. |
| `username`, `password` | oui | Compte Indexer en lecture seule. |
| `verify_tls` | non | `true` par défaut ; conserve la vérification des certificats TLS. |
| `alerts_index` | non | Index à lire ; `wazuh-alerts-*` par défaut. |
| `batch_size` | non | Nombre maximal de résultats par contrôle ; `100` par défaut, maximum `1000`. |

Pour plusieurs clients, configurez leurs jetons dans `SOC_TENANTS_JSON`, puis
associez chaque source Wazuh au bon `tenant_id`. Les labels Wazuh tels que
`ClientA` ou `ClientB` servent au filtre des groupes dans l’interface ; ils ne
remplacent pas le `tenant_id`.

IRIS est désactivé par défaut. Pour l’activer, fournissez ensemble
`IRIS_BASE_URL`, `IRIS_API_KEY` et `IRIS_CASE_ID`. Ne mettez jamais de mot de
passe ou de clé dans le dépôt. `verify_tls: false` est réservé aux essais
locaux avec un certificat non approuvé.

## Accès réseau et sécurité

Par défaut, le serveur écoute sur `0.0.0.0:8080` et affiche les URL du dashboard
disponibles. Depuis un autre poste, ouvrez `http://<IP_DU_SERVEUR>:8080/`.
Autorisez le port TCP 8080 dans le pare-feu uniquement sur le réseau de
confiance nécessaire.

Le serveur utilise HTTP sans chiffrement. Ne l’exposez pas directement à
Internet ; utilisez un reverse proxy HTTPS et un pare-feu pour les accès
distants. Utilisez des comptes Wazuh en lecture seule et des secrets fournis
par l’environnement ou un gestionnaire de secrets.

## API

Les routes `/api/...` attendent l’en-tête `Authorization: Bearer <jeton>`.
Elles renvoient uniquement les données du client associé au jeton.

| Méthode et route | Usage |
| --- | --- |
| `GET /health` | Santé du service, sans authentification. |
| `GET /api/dashboard` | Compteurs et sévérités du client. |
| `GET /api/clients` | Groupes Wazuh présents pour le client du jeton connecté. |
| `GET /api/wazuh/status` | État des sources Wazuh du client, dernier contrôle, dernière alerte et erreurs éventuelles. |
| `GET /api/control/ai` | État de la file IA et 100 derniers traitements. |
| `PATCH /api/control/ai` | Pause/reprise globale, corps `{"enabled":false}` ou `{"enabled":true}`. |
| `GET /api/alerts?limit=100&since=...` | Groupes d’alertes récents ; `since` est une date RFC3339. |
| `POST /api/alerts` | Ingestion manuelle d’une alerte JSON Wazuh. |
| `GET /api/incidents?status=open&limit=100` | Liste d’incidents ; statut facultatif. |
| `GET /api/incidents/{id}` | Incident, alertes liées et feedback. |
| `PATCH /api/incidents/{id}` | Modification de `status` et/ou ajout de `feedback`. |
| `POST /api/incidents/{id}/analyze` | Analyse manuelle avec Ollama. |
| `POST /api/incidents/{id}/queue` | Forcer une nouvelle analyse via la file persistante. |
| `DELETE /api/incidents/{id}/queue` | Retirer de la file un traitement en attente ou en échec. |

## Traitement des alertes et de l’IA

Les alertes de niveau Wazuh inférieur à 10 sont regroupées sur six heures ;
à partir du niveau 10, sur 30 minutes. Les incidents ouverts ou en cours
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
