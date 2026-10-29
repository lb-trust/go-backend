# Go SOC Backend

Backend SOC multi-client écrit en Go, inspiré du flux du projet
[soc-backend](https://github.com/lb-trust/soc-backend). Wazuh reste la source
d'alertes ; le backend les regroupe et les déduplique, ouvre et corrèle des
incidents, puis peut demander une analyse à Ollama et publier uniquement les
analyses automatiques qualifiées dans la timeline IRIS DFIR.

Ce projet est distribué sous licence GPL-3.0 ; voir [LICENSE](./LICENSE).

## Fonctionnalités

- API HTTP JSON avec authentification par jeton et cloisonnement des données
  par client.
- Stockage SQLite persistant, sans service de base de données externe.
- Ingestion manuelle d'alertes Wazuh et collecte périodique optionnelle du
  Wazuh Indexer en lecture seule.
- Regroupement par client, règle et agent ; fenêtre glissante de six heures
  pour les alertes de niveau inférieur à 10, de 30 minutes à partir du niveau
  10.
- Déduplication des identifiants Wazuh et calcul d'occurrences, IP sources,
  score de risque et sévérité.
- Corrélation des incidents par agent ou IP source sur 30 minutes.
- Analyse automatique après 40 occurrences d'alerte faible sur six heures ou
  immédiatement à partir du niveau Wazuh 10. Les tentatives échouées sont
  réessayées jusqu'à trois fois ; une analyse déjà produite n'est pas
  recalculée si seule sa publication IRIS échoue.
- Analyse manuelle d'un incident via Ollama.
- Publication IRIS désactivée par défaut ; elle n'envoie que les analyses
  automatiques qualifiées, jamais les alertes brutes.
- Tableau de bord web léger intégré, sans dépendance JavaScript externe :
  filtrage des incidents, choix et mémorisation des colonnes affichées,
  pause/reprise des analyses et mise en file forcée.

## Prérequis et lancement

Go 1.24 ou plus récent est nécessaire. Démarrez simplement le serveur :

```powershell
go run .\cmd\soc-backend
```

Au premier démarrage, un jeton API aléatoire de 20 caractères est créé pour le
client `client-a` et affiché dans les journaux du serveur. Il est conservé dans
`.soc-api-token` et réutilisé après un redémarrage. Gardez ce fichier secret et
ne le partagez pas ; il est ignoré par Git. Pour régénérer le jeton, arrêtez le
serveur, supprimez `.soc-api-token`, puis redémarrez-le. Pour une configuration
multi-client ou un jeton géré par votre environnement, `SOC_TENANTS_JSON` reste
disponible.

Le serveur écoute par défaut sur toutes les interfaces (`0.0.0.0:8080`) et
crée `soc.db` dans le répertoire courant. Au démarrage, il affiche les URL du
tableau de bord pour les adresses IPv4 détectées. Depuis une autre machine du
même réseau, ouvrez `http://<IPv4 affichée>:8080/` et connectez-vous avec le
jeton API généré.

Si la page ne répond pas, vérifiez que les deux machines sont sur le même
réseau et que le pare-feu Windows autorise les connexions entrantes TCP sur le
port 8080 (sur un réseau privé de confiance). Le serveur utilise HTTP sans
chiffrement : ne l'exposez pas directement à Internet ; utilisez un reverse
proxy HTTPS et un pare-feu si un accès plus large est nécessaire.

Ouvrez `http://127.0.0.1:8080/` sur la machine qui exécute le serveur. La page
n'utilise aucun framework ni ressource externe.
La pause IA est globale au backend, persistante après redémarrage, et ne bloque
pas la collecte Wazuh. Les analyses en attente restent dans la file et seront
traitées à la reprise ; une requête Ollama déjà démarrée peut se terminer.
« Forcer l'analyse » remet l'incident en file, même s'il a déjà été analysé.

## Configuration

| Variable | Défaut | Description |
| --- | --- | --- |
| `SOC_TENANTS_JSON` | généré automatiquement | Objet JSON `jeton: identifiant_client`; permet une configuration multi-client. |
| `SOC_API_TOKEN_FILE` | `.soc-api-token` | Fichier local qui conserve le jeton généré automatiquement. |
| `SOC_DB_PATH` | `soc.db` | Chemin de la base SQLite. |
| `SOC_HOST` / `SOC_PORT` | `0.0.0.0` / `8080` | Adresse et port d'écoute. Utilisez `127.0.0.1` pour limiter l'accès à la machine locale. |
| `WAZUH_SOURCES_JSON` | `[]` | Sources Wazuh Indexer à interroger. |
| `WAZUH_POLL_SECONDS` | `60` | Intervalle de collecte, minimum 15 secondes. |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Instance Ollama. |
| `OLLAMA_MODEL` | `llama3.1` | Modèle d'analyse. |
| `IRIS_BASE_URL` | désactivé | Origine HTTPS IRIS, sans chemin final. |
| `IRIS_API_KEY` | désactivé | Clé API IRIS ; jamais incluse dans les journaux. |
| `IRIS_CASE_ID` | désactivé | Identifiant numérique du cas IRIS cible. |

Le filtre Clients du tableau de bord affiche tous les clients configurés dans
`SOC_TENANTS_JSON` et permet d'en cocher plusieurs. Il fonctionne avec le jeton
déjà utilisé pour se connecter ; aucune création de jeton supplémentaire ni
variable d'accès dédiée n'est nécessaire.

Exemple de collecte Wazuh. Utilisez un compte de service en lecture seule et
laissez `verify_tls` à `true` en environnement normal :

```powershell
$env:WAZUH_SOURCES_JSON='[{"tenant_id":"client-a","url":"https://wazuh-indexer.example.lan:9200","username":"soc-reader","password":"secret-de-remplacement","verify_tls":true,"alerts_index":"wazuh-alerts-*","batch_size":100}]'
```

Pour activer la publication, configurez **ensemble** les trois variables IRIS :

```powershell
$env:IRIS_BASE_URL='https://iris.example.lan:8443'
$env:IRIS_API_KEY='cle-api-stockee-hors-du-depot'
$env:IRIS_CASE_ID='123'
```

Les certificats TLS Wazuh et IRIS doivent être approuvés par le système. Les
secrets doivent être fournis par l'environnement ou un gestionnaire de secrets,
jamais enregistrés dans le dépôt. `verify_tls: false` est réservé aux essais
locaux avec certificats non approuvés.

## API

Les routes `/api/...` attendent `Authorization: Bearer <jeton>` et ne renvoient
que les données du client associé au jeton. Dans le tableau de bord, le filtre
« Groupes client » utilise les valeurs `agent.labels.group` des alertes Wazuh,
par exemple `ClientA` et `ClientB`, pour choisir les groupes affichés.
Copiez le jeton affiché au démarrage :

```powershell
$env:SOC_API_TOKEN='coller-ici-le-jeton-affiche'
$headers = @{ Authorization = "Bearer $env:SOC_API_TOKEN" }
Invoke-RestMethod http://127.0.0.1:8080/api/dashboard -Headers $headers
```

| Méthode et route | Usage |
| --- | --- |
| `GET /health` | Santé du service, sans authentification. |
| `GET /api/dashboard` | Compteurs et sévérités du client. |
| `GET /api/clients` | Liste les groupes Wazuh présents pour le client du jeton connecté. |
| `GET /api/control/ai` | État de la file IA et 100 derniers traitements. |
| `PATCH /api/control/ai` | Pause/reprise globale, corps `{"enabled":false}` ou `{"enabled":true}`. |
| `GET /api/alerts?limit=100&since=...` | Groupes d'alertes récents. `since` est RFC3339. |
| `POST /api/alerts` | Ingestion d'une alerte JSON Wazuh. |
| `GET /api/incidents?status=open&limit=100` | Liste d'incidents, avec statut facultatif. |
| `GET /api/incidents/{id}` | Incident, alertes liées et feedback. |
| `PATCH /api/incidents/{id}` | Modification de `status` et/ou ajout de `feedback`. |
| `POST /api/incidents/{id}/analyze` | Analyse manuelle avec Ollama. |
| `POST /api/incidents/{id}/queue` | Forcer une nouvelle analyse via la file persistante. |
| `DELETE /api/incidents/{id}/queue` | Retirer de la file un traitement en attente ou en échec. |

Statuts d'incident autorisés : `open`, `investigating`, `resolved` et
`false_positive`. Exemple :

## Développement et tests

```powershell
go test ./...
go vet ./...
```
