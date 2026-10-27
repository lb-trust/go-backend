# Intégration de Wazuh Indexer avec le backend SOC

## Objectif

Ce guide décrit la configuration d'une collecte périodique des alertes
Wazuh Indexer par le backend SOC. Le collecteur interroge l'API de recherche
de l'Indexer en lecture seule, puis transmet les alertes au stockage et aux
services du backend.

```text
Wazuh Manager
    |
    v
Wazuh Indexer (HTTPS, port 9200)
    |
    | Recherche périodique en lecture seule
    v
Backend SOC (API HTTP, port 8080 par défaut)
    |
    v
Base SQLite et tableau de bord SOC
```

Les noms d'hôtes, adresses, chemins et identifiants ci-dessous sont des
exemples à remplacer par les valeurs de l'environnement cible.

## Prérequis

- Le backend Go SOC est installé et peut être lancé sur l'hôte collecteur.
- L'hôte du backend peut joindre le Wazuh Indexer sur le port TCP `9200`.
- Le certificat TLS présenté par l'Indexer est approuvé par le système
  d'exploitation du backend.
- Un tenant est configuré dans le backend. Sans configuration spécifique,
  le backend crée le tenant `client-a` et un jeton API au premier démarrage.
- Un compte Wazuh dédié, limité à la lecture des alertes, est disponible.

## 1. Vérifier la disponibilité de l'Indexer

Sur l'hôte qui exécutera le backend, vérifiez l'accès réseau en remplaçant
`<INDEXER_HOST>` par le nom DNS ou l'adresse de l'Indexer :

```bash
nc -vz <INDEXER_HOST> 9200
```

Vérifiez ensuite que le service HTTPS répond :

```bash
curl -i https://<INDEXER_HOST>:9200/
```

Une réponse `401 Unauthorized` sans identifiants est normale : elle confirme
que l'Indexer répond et requiert une authentification. Si la vérification TLS
échoue, installez l'autorité de certification appropriée dans le magasin de
certificats approuvés du système. N'utilisez pas `curl -k` comme solution
permanente et ne désactivez pas la vérification TLS du collecteur en
production.

## 2. Créer un compte de lecture dédié

Dans la gestion de la sécurité Wazuh, créez un compte de service et un rôle
adaptés à la version et à la politique de l'environnement. Le compte doit
disposer uniquement des permissions nécessaires :

- lecture (`read`) sur le motif d'index des alertes, généralement
  `wazuh-alerts-*` ;
- permission de recherche en lecture seule au niveau cluster, si elle est
  requise par la configuration Wazuh (par exemple
  `cluster_composite_ops_ro`).

N'utilisez pas un compte administrateur pour la collecte. Testez les
permissions avec une recherche sur les alertes :

```bash
curl --user '<INDEXER_USER>' \
  'https://<INDEXER_HOST>:9200/wazuh-alerts-*/_search?size=1'
```

`curl` demande le mot de passe de manière interactive. Une réponse JSON
contenant des résultats confirme que le compte peut effectuer cette recherche.
Une interdiction sur une API de listing telle que `_cat/indices` n'empêche pas
nécessairement la collecte : le backend utilise l'API `_search`.

## 3. Configurer la source Wazuh

Le backend lit la variable d'environnement `WAZUH_SOURCES_JSON`. Elle contient
un tableau JSON de sources. Exemple de structure :

```json
[
  {
    "tenant_id": "client-a",
    "url": "https://<INDEXER_HOST>:9200",
    "username": "<INDEXER_USER>",
    "password": "<SECRET>",
    "verify_tls": true,
    "alerts_index": "wazuh-alerts-*",
    "batch_size": 100
  }
]
```

| Champ | Description |
| --- | --- |
| `tenant_id` | Tenant SOC auquel rattacher les alertes. Il doit déjà être configuré dans le backend. |
| `url` | Origine HTTPS de l'Indexer, sans chemin d'API. |
| `username` / `password` | Identifiants du compte de lecture dédié. |
| `verify_tls` | Vérifie la chaîne de certificats TLS. Laisser `true` en environnement normal. |
| `alerts_index` | Motif d'index à rechercher ; `wazuh-alerts-*` par défaut. |
| `batch_size` | Nombre maximal de résultats demandé par interrogation ; valeur par défaut `100`, maximum `1000`. |

Pour un essai ponctuel dans un shell Bash, définissez la variable avant le
lancement du backend :

```bash
export WAZUH_SOURCES_JSON='[{"tenant_id":"client-a","url":"https://<INDEXER_HOST>:9200","username":"<INDEXER_USER>","password":"<SECRET>","verify_tls":true,"alerts_index":"wazuh-alerts-*","batch_size":100}]'
export WAZUH_POLL_SECONDS=60
go run ./cmd/soc-backend
```

Remplacez les valeurs entre chevrons avant l'exécution. Ne saisissez pas un
secret réel dans une commande enregistrée dans l'historique du shell. Pour un
déploiement durable, injectez les variables à partir d'un gestionnaire de
secrets ou d'un fichier d'environnement protégé, accessible uniquement au
compte de service. Ne versionnez jamais les identifiants.

`WAZUH_POLL_SECONDS` définit l'intervalle de collecte : `60` secondes par
défaut et `15` secondes minimum. Chaque `tenant_id` indiqué dans les sources
doit correspondre à un tenant configuré ; avec la configuration par défaut,
utilisez `client-a`.

## 4. Démarrer le backend et vérifier la collecte

Depuis le répertoire du projet :

```bash
go run ./cmd/soc-backend
```

Le backend écoute sur le port `8080` par défaut. Les journaux permettent de
repérer les erreurs de connexion, d'authentification, de permissions, de TLS
ou d'ingestion.

Dans un second terminal, définissez le jeton API SOC. Par défaut, il est
conservé dans `.soc-api-token` après sa génération au premier démarrage :

```bash
export SOC_API_TOKEN="$(cat .soc-api-token)"
```

Vérifiez le service, puis consultez le tableau de bord et les alertes :

```bash
curl -sS http://127.0.0.1:8080/health
curl -sS -H "Authorization: Bearer ${SOC_API_TOKEN}" \
  http://127.0.0.1:8080/api/dashboard
curl -sS -H "Authorization: Bearer ${SOC_API_TOKEN}" \
  'http://127.0.0.1:8080/api/alerts?limit=5'
```

Les routes `/api/...` requièrent un jeton API valide. Le jeton SOC est distinct
du mot de passe du compte Wazuh.

## 5. Format des timestamps

Le backend accepte les timestamps RFC3339/RFC3339Nano, par exemple
`2026-10-27T15:14:03.248+01:00`, ainsi que le format Wazuh avec décalage
compact, par exemple `2026-10-27T15:14:03.248+0100`. Les instants sont
normalisés en UTC avant leur stockage.

Après une modification du parseur, validez le code avec :

```bash
gofmt -w internal/soc/backend.go
go test ./...
```

## Dépannage

| Symptôme | Vérifications |
| --- | --- |
| Connexion refusée ou délai dépassé | Résolution DNS, adresse de l'Indexer, écoute du port `9200`, routage et règles de pare-feu entre les hôtes. |
| Erreur de certificat | Chaîne TLS présentée par l'Indexer, autorité de certification approuvée par le système et correspondance entre le nom utilisé et le certificat. |
| Réponse `401` de l'Indexer | Identifiant et mot de passe du compte de lecture. |
| Réponse `403` sur `_search` | Permissions de lecture sur le motif d'index et permissions cluster requises par la version Wazuh. |
| Erreur sur `_cat/indices`, mais `_search` fonctionne | Les permissions de listing sont distinctes ; le backend collecte avec `_search`. |
| Erreur d'ingestion liée à `timestamp` | Vérifier que la valeur est RFC3339/RFC3339Nano ou utilise un décalage Wazuh compact, tel que `+0100`. |
| API SOC répond « jeton API invalide » | Vérifier la valeur du jeton SOC et l'en-tête `Authorization: Bearer ...`. |
| Aucune alerte dans l'API | Vérifier les journaux du collecteur, `WAZUH_SOURCES_JSON`, le tenant ciblé, le motif d'index et la plage temporelle des alertes disponibles. |

## Sécurité et exploitation

- Utilisez un compte Wazuh dédié avec des permissions minimales.
- Gardez `verify_tls` à `true` et faites approuver les certificats nécessaires
  par le système.
- Protégez le mot de passe Wazuh et le jeton API SOC ; renouvelez tout secret
  exposé accidentellement.
- Limitez les accès réseau aux seuls systèmes qui en ont besoin. Le backend
  utilise HTTP sans chiffrement par défaut ; ne l'exposez pas directement à
  Internet.
- Pour une exploitation durable, exécutez le backend sous un compte de service
  avec un mécanisme de supervision et de redémarrage adapté à la plateforme.
- Sauvegardez la base SQLite selon une procédure testée et surveillez les
  journaux après les redémarrages et les mises à jour.
