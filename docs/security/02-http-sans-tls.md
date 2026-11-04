# Faille 2 — Accès HTTP sans chiffrement TLS

**Sévérité relevée :** élevée  
**Composant concerné :** serveur HTTP du backend et exposition réseau  
**État :** à corriger au déploiement avant tout accès depuis un réseau non fiable.

## Problème et impact

Le backend sert HTTP sans TLS. Sa configuration par défaut écoute sur toutes
les interfaces. Les appels du dashboard transmettent le jeton API dans
l’en-tête `Authorization`, et les réponses contiennent des alertes, incidents,
analyses et informations client.

Sur un réseau où un tiers peut observer ou modifier le trafic, HTTP permet
l’interception du jeton et des données, leur rejeu, ou la modification des
réponses. Un jeton intercepté peut donner accès aux routes API jusqu’à sa
révocation.

## Architecture recommandée

Terminez TLS sur un reverse proxy maintenu. Le navigateur doit utiliser
exclusivement HTTPS. Le reverse proxy relaie le trafic au backend en HTTP sur
la boucle locale, inaccessible aux autres machines :

```text
Navigateur ── HTTPS :443 ──> Nginx ── HTTP :8080 (127.0.0.1) ──> Backend SOC
```

Cette architecture évite de modifier le code du service. Le détail de
l’installation de Nginx, Certbot, du service systemd, du pare-feu et des tests
se trouve dans le [guide Debian 13](../../SECURISER-HTTP-DEBIAN-13.md).

## Mesures à appliquer

1. Obtenir un certificat valide pour un nom DNS contrôlé par l’organisation,
   via une autorité publique ou interne approuvée.
2. Configurer le backend avec `SOC_HOST=127.0.0.1` et un port local connu.
3. Configurer le reverse proxy pour transmettre les requêtes à cette adresse,
   et conserver l’en-tête `Authorization` utilisé par le dashboard.
4. Exposer uniquement les ports nécessaires du reverse proxy. Bloquer le port
   backend dans les pare-feu du serveur, du fournisseur cloud et du réseau.
5. Rediriger HTTP vers HTTPS ; rejeter les noms d’hôtes inconnus.
6. Protéger l’accès administrateur à Nginx et à ses clés privées. Ne pas
   afficher, copier ou committer les clés de certificat.
7. Superviser l’expiration et vérifier automatiquement le renouvellement des
   certificats.
8. Envisager HSTS après vérification complète du HTTPS. Ne pas activer
   `includeSubDomains` ou `preload` sans audit des sous-domaines.

Ne faites pas confiance à un en-tête `X-Forwarded-Proto` ou à une adresse
transmise par le client pour une décision de sécurité côté backend : ces
en-têtes doivent être définis par le proxy de confiance et le backend ne doit
pas être accessible en contournant ce proxy.

## Contrôles de validation

- Le dashboard est accessible avec un certificat valide à son nom DNS en
  `https://`.
- Le navigateur n’affiche aucun avertissement TLS et la connexion API reste
  fonctionnelle.
- `http://<nom-dns>/` redirige vers HTTPS et aucun lien de production ne reste
  en HTTP.
- Le backend écoute sur `127.0.0.1`, pas sur `0.0.0.0` ou `[::]`.
- Depuis une autre machine, le port backend n’est pas joignable ; le port 443
  ne donne accès qu’au proxy.
- Le renouvellement de certificat a été testé et une alerte d’expiration est
  configurée.

## Limites

TLS protège le transport navigateur → proxy. Si le proxy et le backend sont
sur deux machines, leur lien doit également être chiffré et filtré. TLS ne
remplace pas l’authentification, les restrictions de réseau, la protection des
secrets ou le chiffrement des données stockées.

Pour les autres risques constatés, voir [la revue de sécurité](../../SECURITY-REVIEW.md).
