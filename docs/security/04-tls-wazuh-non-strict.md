# Faille 4 — Connexion Wazuh sans TLS strict

**Sévérité relevée :** moyenne  
**Composants concernés :** `WAZUH_SOURCES_JSON`, validation de configuration et
client Wazuh  
**État :** la configuration de production doit utiliser HTTPS vérifié.

## Problème et impact

La configuration accepte une URL Wazuh en HTTP. Elle permet également
`"verify_tls": false`. Le client envoie les identifiants Indexer avec HTTP
Basic Auth et reçoit les alertes.

Avec HTTP, les identifiants et données peuvent être observés ou modifiés sur
le réseau. Avec une validation TLS désactivée, un attaquant réseau capable
d’intercepter la connexion peut présenter un certificat non approuvé et
usurper l’Indexer, même si l’URL commence par HTTPS.

La valeur par défaut de `verify_tls` est `true` quand le champ est absent. Une
URL HTTPS et une vérification TLS explicite ne suffisent cependant pas si la
machine ne fait pas confiance à l’autorité ayant signé le certificat.

## Configuration attendue en production

Une entrée de source doit utiliser une origine HTTPS et la vérification TLS :

```json
{
  "tenant_id": "client-a",
  "url": "https://indexer.example.lan:9200",
  "username": "soc-reader",
  "password": "<fourni par un gestionnaire de secrets>",
  "verify_tls": true,
  "alerts_index": "wazuh-alerts-*",
  "batch_size": 100
}
```

Le mot de passe ci-dessus est un marqueur explicatif : ne le remplacez pas
dans un fichier versionné. Placez la valeur réelle uniquement dans un
gestionnaire de secrets ou dans le fichier d’environnement protégé du service.

Pour un certificat émis par une autorité interne :

1. Installez le certificat de l’autorité racine/intermédiaire approuvée dans le
   magasin de confiance du système Debian selon la procédure de l’organisation.
2. Actualisez le magasin de certificats du système.
3. Assurez-vous que le certificat présenté par l’Indexer est valide, non expiré
   et comporte le nom DNS utilisé dans `url` dans ses Subject Alternative Names.
4. Vérifiez que le backend s’exécute dans un environnement qui utilise ce
   magasin de confiance.

Ne désactivez pas la vérification pour contourner une erreur de certificat.
Corrigez la chaîne, le nom DNS, les dates ou le magasin de confiance.

## Réduire les privilèges du compte Indexer

- Utilisez un compte technique distinct pour le backend.
- Accordez uniquement la lecture sur les index Wazuh nécessaires.
- N’utilisez pas un compte administrateur Indexer.
- Limitez les sources réseau autorisées à joindre l’Indexer.
- Faites tourner les identifiants si une source a déjà utilisé HTTP ou une
  validation TLS désactivée.

## Contrôles de validation

- La valeur `url` de chaque source commence par `https://`.
- `verify_tls` vaut `true` ou est absent (le défaut du backend est alors
  `true`).
- Depuis la machine du backend, le certificat de l’Indexer est approuvé et son
  nom correspond à l’hôte configuré.
- La collecte fonctionne sans erreur de certificat.
- Un test d’environnement contrôlé avec un certificat invalide est rejeté ;
  n’effectuez pas ce test contre une source de production sans autorisation.
- Le compte technique ne peut pas écrire dans les index ni accéder à des
  données non nécessaires.

## Durcissement possible du code

Pour réduire les erreurs de configuration, une évolution du backend pourrait
refuser les URL `http://` et `verify_tls: false` hors d’un mode de développement
explicitement activé. Cette modification changerait la compatibilité des
configurations locales existantes : inventoriez les sources et certificats,
prévoyez une migration, puis ajoutez des tests de validation avant de
l’imposer.

En attendant ce durcissement, contrôlez la configuration réellement chargée au
démarrage et n’autorisez pas d’exception TLS en production.

Pour les autres risques constatés, voir [la revue de sécurité](../../SECURITY-REVIEW.md).
