# Revue de sécurité

**Projet :** `lb-trust/go-backend`  
**Date :** 30 octobre 2026  
**Périmètre :** revue statique du backend Go, de l’authentification HTTP,
de la configuration, de la persistance SQLite, des clients Wazuh/Ollama/IRIS
et des consignes de déploiement.  
**Contexte :** mise en service envisagée avec des données SOC sensibles.

## Résumé

La revue a identifié deux risques élevés et deux risques moyens. Le jeton
versionné et l’exposition HTTP sont prioritaires avant toute mise en service.
Le jeton n’a pas été supprimé ni remplacé dans ce changement afin de ne pas
modifier l’accès existant ; il doit être révoqué et remplacé par l’opérateur.

La journalisation du jeton généré a été supprimée sans changer le mécanisme
d’authentification, le format du jeton ni le fichier où il est conservé. Le
backend indique désormais dans ses journaux le chemin du fichier, pas le secret.

## Constats

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🟠 HIGH | `cmd/soc-backend/.soc-api-token` | 1 | Un jeton API est suivi par Git. Une personne ayant accès au dépôt peut l’utiliser pour accéder aux données ou opérations du client associé si ce jeton est actif. | 8/10 |
| 2 | 🟠 HIGH | `cmd/soc-backend/main.go` | 48-62 | Le serveur écoute en HTTP sans TLS et, par défaut, sur toutes les interfaces. Un attaquant sur le chemin réseau peut intercepter et rejouer les jetons d’accès ainsi que lire le trafic SOC. | 9/10 |
| 3 | 🟡 MEDIUM | `cmd/soc-backend/main.go` | 29-31 (corrigé) | Le jeton généré était écrit dans les journaux de démarrage, qui peuvent être accessibles ou centralisés. Le démarrage n’écrit désormais que le chemin du fichier du jeton. | 9/10 |
| 4 | 🟡 MEDIUM | `internal/soc/config.go` | 106, 161-170 | La configuration permet une source Wazuh en HTTP ou avec la vérification TLS désactivée. Les identifiants Basic Auth et les alertes peuvent alors être interceptés ou modifiés. | 9/10 |

### Détails et remédiations

#### 1. Jeton API versionné — HIGH

Le fichier `cmd/soc-backend/.soc-api-token` contient un secret suivi par Git.
Le backend accepte ce jeton comme authentification et l’associe à un client.
La suppression du fichier de la branche courante ne suffit pas si le secret est
présent dans l’historique, les clones, les journaux ou les sauvegardes.

**À faire avant mise en service :**

1. Révoquer le jeton exposé et en générer un nouveau.
2. Retirer le fichier secret du suivi Git et empêcher son ajout futur.
3. Purger le secret de l’historique Git selon la procédure de l’hébergeur, puis
   vérifier les clones, forks, caches CI et sauvegardes.
4. Stocker les jetons runtime dans un gestionnaire de secrets ou un fichier
   protégé, accessible uniquement au compte de service.

Ces opérations n’ont pas été effectuées ici car la rotation et le retrait du
jeton peuvent modifier l’accès existant.

#### 2. HTTP sans chiffrement — HIGH

Le serveur utilise `http.ListenAndServe` et le réglage par défaut écoute sur
`0.0.0.0`. L’en-tête `Authorization` contient le jeton API. HTTP ne protège ni
ce jeton ni le contenu des requêtes contre l’écoute ou la modification réseau.

**À faire avant mise en service :**

- Terminer TLS sur un reverse proxy maintenu et correctement configuré.
- Lier le backend à `127.0.0.1` lorsqu’il est derrière le proxy.
- Bloquer l’accès réseau direct au port du backend ; autoriser uniquement le
  proxy depuis les réseaux nécessaires.
- Rediriger HTTP vers HTTPS au proxy et activer HSTS sur l’origine HTTPS.
- Ne jamais exposer directement le serveur HTTP du backend à Internet ou à un
  réseau non fiable.

#### 3. Secret exposé dans les journaux — MEDIUM, corrigé

Au démarrage, le jeton généré était inclus dans une ligne de journal. Les
journaux applicatifs, système et centralisés doivent être traités comme des
emplacements susceptibles d’être consultés ou conservés.

**Correction appliquée :** le secret n’est plus écrit dans les journaux. Le
backend conserve le même mécanisme de création et de stockage du jeton ; seul
le chemin du fichier est journalisé. La documentation indique de lire ce
fichier localement pour se connecter.

**À faire :** faire tourner les jetons qui auraient déjà été copiés dans les
journaux et limiter l’accès/rétention des journaux existants.

#### 4. Connexion Wazuh sans TLS strict — MEDIUM

La configuration accepte HTTP et `verify_tls: false`. Le client Wazuh envoie
un nom d’utilisateur et un mot de passe via Basic Auth.

**À faire avant mise en service :**

- Utiliser exclusivement HTTPS avec des certificats valides vérifiés.
- Refuser `verify_tls: false` et les URL HTTP en production ; réserver les
  exceptions aux environnements de développement isolés.
- Utiliser des comptes Indexer dédiés en lecture seule, avec accès limité aux
  seuls index nécessaires, et faire tourner leurs secrets.

## Renforcements recommandés avant production

Les éléments ci-dessous sont des recommandations de durcissement. La revue
statique ne permet pas de confirmer la configuration réelle de l’infrastructure.

### Secrets et identité

- Utiliser un gestionnaire de secrets, la rotation et une procédure de révocation.
- Éviter les jetons partagés entre personnes et services ; définir propriétaire,
  périmètre et durée de vie.
- Contrôler l’accès aux fichiers de jetons, aux variables d’environnement et aux
  journaux de service.
- Envisager une authentification centralisée et MFA pour les opérateurs si
  l’application est accessible à plusieurs personnes.

### Données au repos et cycle de vie

- Chiffrer le volume contenant SQLite, ses fichiers WAL/SHM et les sauvegardes.
- Limiter les permissions du fichier DB et du répertoire au compte de service.
- Définir une durée de conservation des alertes, incidents, analyses IA et
  sauvegardes, ainsi qu’une procédure de suppression vérifiable.
- Tester restauration, intégrité, accès et chiffrement des sauvegardes.

### Réseau et disponibilité

- Filtrer les connexions entrantes aux seuls postes/réseaux nécessaires.
- Limiter les sorties réseau du backend à Wazuh, Ollama, IRIS, DNS et aux
  services d’infrastructure nécessaires.
- Ajouter des limites de débit et une surveillance des erreurs/authentifications
  répétées si le service est accessible depuis un réseau partagé.
- Définir sauvegardes, supervision disque, alertes d’espace et procédure de
  reprise après incident.

### IA et contenu non fiable

- Considérer les descriptions et champs d’alertes comme des données non fiables :
  ils peuvent contenir des instructions adverses destinées au modèle.
- Garder les alertes séparées des instructions système et limiter explicitement
  les actions que le modèle peut déclencher.
- Vérifier les analyses avant publication vers IRIS ; ne pas laisser une sortie
  du modèle autoriser seule une action de réponse ou de remédiation.
- Examiner les données envoyées à Ollama et IRIS, leur localisation, leur
  rétention et les droits des comptes associés.

### Exploitation et vérification

- Exécuter le backend sous un compte dédié non privilégié et maintenir Go, les
  dépendances, le système et le reverse proxy à jour.
- Ajouter une analyse automatisée des dépendances et des secrets dans la CI,
  sans publier les secrets ni les données SOC dans les journaux d’exécution.
- Formaliser une procédure de réponse aux incidents : révocation des jetons,
  isolement, collecte des journaux et restauration.
- Avant ouverture du service, faire valider l’architecture réseau, les règles
  de pare-feu, les permissions et les sauvegardes dans l’environnement réel.

## Limites

Cette revue est statique et limitée au code et aux documents du dépôt. Elle ne
remplace pas un test d’intrusion autorisé, une revue de configuration du
serveur/proxy/firewall, une analyse de la chaîne de livraison ni une validation
des pratiques de sauvegarde et de gestion des secrets en production.
