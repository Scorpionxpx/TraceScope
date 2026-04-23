# TraceScope (GitHub Pages)

Site statique pour analyser des captures PktMon.

## Important

Un fichier ETL est souvent binaire. Sur GitHub Pages (sans backend), il faut le convertir en texte avant analyse:

pktmon etl2txt "capture.etl" -o "capture.txt"

Ensuite, chargez le fichier TXT dans le site.

## Publication GitHub Pages

1. Creez un depot GitHub (ex: tracescope).
2. Uploadez le contenu de ce dossier a la racine du depot.
3. Dans GitHub, ouvrez Settings > Pages.
4. Source: Deploy from a branch.
5. Branche: main, dossier: /(root).
6. Enregistrez, puis ouvrez l URL fournie.

## Fichiers

- index.html: interface
- styles.css: design et responsive
- app.js: lecture et analyse des fichiers
