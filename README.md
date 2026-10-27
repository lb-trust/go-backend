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

## Prérequis et lancement

Go 1.24 ou plus récent est nécessaire. Dans PowerShell, configurez au minimum
un jeton aléatoire associé à un identifiant client, puis démarrez le serveur :

```powershell
$env:SOC_TENANTS_JSON='{"remplacer-par-un-jeton-long-et-aleatoire":"client-a"}'
$env:SOC_API_TOKEN='remplacer-par-un-jeton-long-et-aleatoire'
go run .\cmd\soc-backend
```

Le serveur écoute sur `127.0.0.1:8080` et crée `soc.db` dans le répertoire
courant. Il utilise HTTP sans chiffrement : gardez-le sur une interface de
confiance, ou placez un reverse proxy HTTPS et un pare-feu devant lui. Ne
l'exposez pas directement à Internet.

## Configuration

| Variable | Défaut | Description |
| --- | --- | --- |
| `SOC_TENANTS_JSON` | requis | Objet JSON `jeton: identifiant_client`. |
| `SOC_DB_PATH` | `soc.db` | Chemin de la base SQLite. |
| `SOC_HOST` / `SOC_PORT` | `127.0.0.1` / `8080` | Adresse et port d'écoute. |
| `WAZUH_SOURCES_JSON` | `[]` | Sources Wazuh Indexer à interroger. |
| `WAZUH_POLL_SECONDS` | `60` | Intervalle de collecte, minimum 15 secondes. |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Instance Ollama. |
| `OLLAMA_MODEL` | `llama3.1` | Modèle d'analyse. |
| `IRIS_BASE_URL` | désactivé | Origine HTTPS IRIS, sans chemin final. |
| `IRIS_API_KEY` | désactivé | Clé API IRIS ; jamais incluse dans les journaux. |
| `IRIS_CASE_ID` | désactivé | Identifiant numérique du cas IRIS cible. |

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
que les données du client associé.

| Méthode et route | Usage |
| --- | --- |
| `GET /health` | Santé du service, sans authentification. |
| `GET /api/dashboard` | Compteurs et sévérités du client. |
| `GET /api/alerts?limit=100&since=...` | Groupes d'alertes récents. `since` est RFC3339. |
| `POST /api/alerts` | Ingestion d'une alerte JSON Wazuh. |
| `GET /api/incidents?status=open&limit=100` | Liste d'incidents, avec statut facultatif. |
| `GET /api/incidents/{id}` | Incident, alertes liées et feedback. |
| `PATCH /api/incidents/{id}` | Modification de `status` et/ou ajout de `feedback`. |
| `POST /api/incidents/{id}/analyze` | Analyse manuelle avec Ollama. |

Statuts d'incident autorisés : `open`, `investigating`, `resolved` et
`false_positive`. Exemple :

```powershell
$headers = @{ Authorization = "Bearer $env:SOC_API_TOKEN" }
Invoke-RestMethod http://127.0.0.1:8080/api/dashboard -Headers $headers
```

## Développement et tests

```powershell
go test ./...
go vet ./...
```
