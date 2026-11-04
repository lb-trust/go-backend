# Faille 3 — Jeton API exposé dans les journaux

**Sévérité relevée :** moyenne  
**Composant concerné :** journal de démarrage dans `cmd/soc-backend/main.go`  
**État :** correction appliquée ; traiter les éventuelles copies historiques.

## Problème

Une ancienne version du backend écrivait le jeton API généré dans les logs de
démarrage. Les journaux système, centralisés, de conteneurs ou de CI sont
souvent accessibles à davantage de personnes que le fichier de secret et
peuvent être conservés ou copiés dans des sauvegardes.

Toute copie de ce jeton doit être considérée comme exposée. La suppression de
la ligne de journal dans le code n’efface pas les journaux déjà produits et ne
révoque pas le jeton.

## Correction déjà appliquée

Le démarrage ne journalise plus la valeur du jeton. Il indique uniquement le
chemin du fichier dans lequel le jeton est conservé. Le mécanisme
d’authentification, le format du jeton et son stockage n’ont pas été modifiés.

## Actions opérateur

1. Déterminez les versions et périodes pendant lesquelles l’ancienne
   journalisation a été utilisée.
2. Si le service a tourné avec cette version, révoquez et remplacez le jeton
   concerné. N’attendez pas de confirmer chaque copie pour le révoquer.
3. Mettez à jour le binaire et redémarrez le service selon la procédure normale.
4. Identifiez les destinations de journaux : journald, fichiers locaux,
   plateforme de collecte, tickets, sauvegardes et pipelines CI.
5. Appliquez la politique de rétention/suppression de l’organisation à ces
   journaux, sans effacer de preuves nécessaires à une investigation ou à une
   obligation de conservation.
6. Limitez les droits de lecture des journaux, des sauvegardes et des consoles
   de centralisation.

La purge des journaux doit respecter les obligations internes et légales.
Lorsque leur conservation est nécessaire, restreignez leur accès, consignez
leur statut de données sensibles et supprimez les copies à l’expiration de la
rétention approuvée.

## Vérifications

- Le code actuel ne formate jamais `GeneratedToken` dans un message de log.
- Un démarrage avec un jeton généré signale le chemin du fichier, sans secret.
- Les journaux actuels et centralisés ne contiennent pas le nouveau jeton.
- Le jeton utilisé pendant la période d’exposition a été remplacé.
- Le fichier contenant le jeton reste lisible uniquement par les comptes
  nécessaires.

Ne collez jamais le jeton lui-même dans une commande de recherche, un ticket ou
un rapport de validation. Contrôlez les journaux de façon à éviter de réafficher
le contenu sensible.

Pour les autres risques constatés, voir [la revue de sécurité](../../SECURITY-REVIEW.md).
