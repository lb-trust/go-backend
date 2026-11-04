# Faille 1 — Jeton API versionné dans Git

**Sévérité relevée :** élevée  
**Composant concerné :** `cmd/soc-backend/.soc-api-token`  
**État :** à traiter par l’administrateur avant la mise en service.

## Problème

Le dépôt contient un fichier de jeton API suivi par Git. Une personne ayant
accès au dépôt, à un clone ou à une archive du dépôt peut récupérer ce secret.
Si le jeton est encore accepté par le backend, il permet d’utiliser les routes
authentifiées avec les droits du client associé.

Retirer le fichier de la dernière version du dépôt ne révoque pas le jeton et
ne l’efface pas de l’historique Git, des clones, des forks, des caches CI ou
des sauvegardes.

## Priorité immédiate : révoquer et remplacer le jeton

Le backend accepte les jetons configurés dans `SOC_TENANTS_JSON`. Le fichier
de jeton généré automatiquement est le mode par défaut lorsque cette variable
n’est pas configurée. Planifiez la rotation avec les personnes et services qui
utilisent actuellement le jeton : leurs sessions devront être reconnectées.

Procédure recommandée :

1. Préparez un nouveau jeton aléatoire, généré par un gestionnaire de secrets
   ou un générateur cryptographique approuvé. Ne le mettez pas dans une
   commande, un ticket, un dépôt ou un journal.
2. Configurez ce jeton pour le même `tenant_id` dans le gestionnaire de secrets
   ou le fichier d’environnement protégé du service.
3. Si une période de transition est nécessaire, configurez temporairement les
   anciens et nouveau jetons pour le même tenant ; informez les utilisateurs
   du délai, puis retirez impérativement l’ancien. Si une révocation immédiate
   est nécessaire, ne gardez pas cette période de chevauchement.
4. Redémarrez le service selon votre procédure de déploiement.
5. Vérifiez que le nouveau jeton autorise les opérations attendues et que
   l’ancien est refusé. Ne mettez jamais les valeurs des jetons dans les
   sorties de vérification.
6. Demandez aux opérateurs de se reconnecter ; les sessions existantes dans le
   navigateur utilisent l’ancien jeton jusqu’à leur effacement ou expiration.

Le format de configuration explicite est un objet JSON `jeton: tenant_id`.
Modifiez-le dans le fichier de secrets du service, pas dans le dépôt. Protégez
ce fichier afin que seul root et le compte de service puissent le lire.

## Retirer le secret du dépôt

Effectuez cette étape **après** la rotation :

1. Ajoutez le chemin exact du fichier à `.gitignore` :

   ```gitignore
   /cmd/soc-backend/.soc-api-token
   ```

2. Retirez le fichier de l’index Git sans effacer la copie locale à l’aide de
   `git rm --cached -- cmd/soc-backend/.soc-api-token`.
3. Vérifiez avec `git status --short` que le fichier local n’est plus suivi et
   que `.gitignore` est inclus dans le changement.
4. Vérifiez que les autres fichiers runtime (base SQLite, WAL/SHM, jetons,
   fichiers d’environnement et sauvegardes) sont également exclus du dépôt.
   Ne supprimez pas de données de production pendant cette vérification.

Le retrait de l’index ne réécrit pas les commits existants. Pour supprimer le
secret de l’historique, coordonnez avec l’administrateur Git une réécriture
historique avec un outil adapté, puis publiez l’historique réécrit. Cette
opération modifie les identifiants de commits et oblige les collaborateurs à
réconcilier ou re-cloner leurs dépôts. Vérifiez également les forks, miroirs,
archives, caches de CI, journaux et sauvegardes. Même après purge, traitez
l’ancien secret comme compromis : sa rotation reste nécessaire.

## Stockage runtime recommandé

- Utilisez un gestionnaire de secrets ou un fichier de configuration hors du
  dépôt, lisible uniquement par root et le compte système du backend.
- Ne placez pas le jeton dans un fichier versionné, une image de conteneur, une
  commande enregistrée dans l’historique shell, un journal ou une URL.
- Limitez les personnes et services autorisés à lire ou renouveler le secret.
- Documentez son propriétaire, son tenant, sa procédure de rotation et de
  révocation.

## Vérifications après correction

- Le nouveau jeton permet la connexion et les opérations autorisées.
- L’ancien jeton est rejeté par l’API après sa révocation.
- Le fichier de secret n’apparaît plus comme fichier suivi dans Git.
- Le chemin du jeton est ignoré par Git et le secret ne se retrouve pas dans le
  diff courant.
- L’historique et les copies du dépôt ont un plan de purge et des responsables
  identifiés.

Pour les autres risques constatés, voir [la revue de sécurité](../../SECURITY-REVIEW.md).
