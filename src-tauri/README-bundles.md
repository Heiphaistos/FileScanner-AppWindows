# Cibles de paquets

`tauri.conf.json` porte `"targets": "all"` pour que la CI Linux produise les
paquets deb, rpm et AppImage.

`tauri.windows.conf.json` ramène la cible à `["nsis"]` sous Windows uniquement.
Tauri fusionne automatiquement `tauri.<plateforme>.conf.json` par-dessus la
configuration de base (`tauri-utils`, `config/parse.rs`), donc aucune option en
ligne de commande n'est nécessaire.

La raison : avec `"all"` sous Windows, le bundler produit **aussi** un MSI.
L'application apparaît alors deux fois dans la liste des applications de Windows,
et désinstaller l'une laisse l'autre pointer sur un dossier supprimé — l'icône
fantôme signalée par Momo.

Le canal de mise à jour ne consomme que l'artefact NSIS : `outils/publier.py`
cherche `FileScanner_<version>_x64-setup.exe` et sa signature.

Ne pas remettre NSIS seul dans `tauri.conf.json` : cela recasserait la CI Linux.
Ne pas retirer `tauri.windows.conf.json` : cela ferait revenir le MSI.
