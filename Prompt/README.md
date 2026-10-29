# Prompts d'analyse SOC

Ce dossier contient deux séries de prompts conçues pour comparer les réponses d'une IA.
Dans chaque série, les trois variantes poursuivent le même objectif, mais utilisent un angle
ou un format de réponse différent.

## Prompts de contexte

Les fichiers `Prompt-contexte` donnent chacun un contexte complet pour analyser des alertes
du backend Go SOC et de Wazuh :

1. `01-contexte-analyse-factuelle.md` : approche centrée sur les faits et leur traçabilité.
2. `02-contexte-analyse-investigation.md` : approche enquête qui compare plusieurs hypothèses.
3. `03-contexte-analyse-decision.md` : approche orientée priorisation et décision de triage.

Pour comparer les contextes, sélectionne **un seul** fichier et utilise-le comme contexte
de l'IA. Les trois sont autonomes et portent sur la même mission.

## Prompts d'alerte

Les fichiers `Prompt-alerte` demandent tous l'analyse d'un résumé d'alerte :

1. `01-analyse-structuree.md` : réponse factuelle et structurée.
2. `02-analyse-contradictoire.md` : analyse qui compare les hypothèses préoccupantes et bénignes.
3. `03-synthese-triage.md` : synthèse courte orientée triage opérationnel.

Remplace dans le prompt choisi le texte entre chevrons par **le même résumé d'alerte**
pour comparer les résultats. Pour une comparaison contrôlée, garde le même modèle, le même
contexte et les mêmes données ; ne change que le prompt à tester.

Avant tout envoi à un service externe, anonymise les secrets et les données personnelles
qui ne sont pas nécessaires à l'analyse.
