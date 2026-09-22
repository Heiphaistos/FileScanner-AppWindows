# 🔍 FileScanner v1.2.4

> Analyseur de sécurité de fichiers — Desktop app Windows (Tauri v2 + Rust + Vue 3)

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Version](https://img.shields.io/badge/version-1.2.4-green)
![Stack](https://img.shields.io/badge/stack-Tauri%20v2%20%7C%20Rust%20%7C%20Vue%203-orange)

---

## ✨ Fonctionnalités

| Module | Description |
|--------|-------------|
| 🔑 **Hash** | MD5, SHA1, SHA256, SHA512 — streaming sur fichiers volumineux |
| 🧬 **MIME réel** | Détection type réel (bypass extension falsifiée) |
| 🪟 **Analyse PE** | Headers, imports, sections, anomalies binaires |
| 📜 **Scripts** | Analyse PowerShell, Batch, VBS, JS — IoCs & obfuscation |
| 🛡️ **YARA** | 50+ règles intégrées — détection heuristique |
| 🦠 **ClamAV** | Lookup MD5/SHA256 dans base locale ClamAV + **auto-update 24h** |
| 🌐 **VirusTotal** | Lookup hash via API VT — **backoff exponentiel 429** |
| 📊 **Export** | JSON, HTML (XSS-safe), TXT, Markdown, PDF |
| 🎯 **Verdict** | Propre / Suspect / Malveillant avec score de confiance |
| 🔒 **Quarantaine** | Neutralisation + déplacement sécurisé des fichiers malveillants |
| 🔄 **Mise à jour auto** | Manifeste signé, vérification au démarrage et à la demande |

---

## 🆕 Nouveautés v1.2.3 / v1.2.4

### 📊 L'export de rapport n'écrivait pas de fichier

Le garde-fou « la destination doit rester sous le répertoire utilisateur »
comparait un chemin canonicalisé à `USERPROFILE`. Sous Windows,
`std::fs::canonicalize` renvoie un chemin verbatim (`\\?\C:\Users\…`) que
`USERPROFILE` n'a pas, et `Path::starts_with` compare les préfixes tels quels :
la vérification était **toujours** en échec. Le répertoire utilisateur est
maintenant canonicalisé lui aussi avant comparaison.

Deux causes secondaires corrigées dans la foulée :

- `raw.contains("..")` rejetait des noms de fichiers légitimes comme
  `rapport_archive..zip.json`. Un `..` dans un nom n'est pas un segment de
  chemin ; le test porte désormais sur `Component::ParentDir`.
- L'échec partait en promesse non gérée : le bouton reprenait son état normal
  et aucun message n'apparaissait, d'où l'impression que l'application
  « ne sauvegardait pas » au lieu de refuser. L'erreur remonte maintenant
  dans l'interface.

Un export HTML a également été ajouté à la version web.

### 🔄 Mise à jour automatique

L'application interroge un manifeste signé
(`filescanner-app.heiphaistos.org/maj/latest.json`) au démarrage, en silence,
puis à la demande via **⟳ Vérifier les mises à jour** en bas de la barre
latérale. Si une version plus récente existe, elle est proposée, téléchargée,
installée, et l'application redémarre seule.

La signature est vérifiée contre une clé publique gravée dans le binaire : un
manifeste ou un installeur modifié en route est refusé. Si le canal est
injoignable, l'application continue de fonctionner sans rien afficher.

> ⚠️ Une version antérieure à 1.2.3 ne contient pas ce module et ne se mettra
> pas à jour toute seule. Installer 1.2.3 ou plus récent une fois à la main ;
> l'automatisme prend le relais ensuite.

### 🪟 Icône fantôme après désinstallation

`bundle.targets` valait `"all"`, ce qui produisait **un MSI en plus** de
l'installeur NSIS sous Windows. L'application apparaissait deux fois dans la
liste des applications de Windows, et désinstaller l'une laissait l'autre
pointer sur un dossier supprimé.

Windows est désormais limité à NSIS par `src-tauri/tauri.windows.conf.json`,
sans toucher aux paquets Linux — voir
[`src-tauri/README-bundles.md`](src-tauri/README-bundles.md).

---

## 🔐 Correctifs de sécurité

| Fix | Sévérité | Description |
|-----|----------|-------------|
| Path Traversal | 🔴 CRITIQUE | Validation stricte des chemins entrants |
| Export path injection | 🔴 CRITIQUE | Chemin de destination validé avant écriture |
| Lecture VBA sans plafond | 🔴 CRITIQUE | Un `.docm` déclarant un octet et se décompressant en gigaoctets tuait le service ; la lecture est bornée |
| Regex `.expect()` → `LazyLock` | 🟠 HAUTE | Pré-compilation — plus de panic potentielle |
| VT backoff exponentiel | 🟠 HAUTE | 3 tentatives × 2^n×500 ms sur 429 / timeout |
| API key RAM purge | 🟠 HAUTE | Clé VT effacée du store Pinia après chaque scan |
| Scan timeout | 🟡 MOYENNE | Timeout global de 2 minutes par analyse |
| CVD bomb protection | 🟡 MOYENNE | Limite 500 MB sur les fichiers CVD avant extraction |
| HTML export XSS | 🟡 MOYENNE | HTML-escape sur toutes les chaînes des rapports |

---

## 📸 Interface

- **Drop Zone** — glisser-déposer un fichier
- **Verdict Display** — résumé visuel + bouton quarantaine (si malveillant)
- **IoC Table** — liste paginée virtuellement (> 100 indicateurs)
- **PE Details** — détails binaires des exécutables Windows
- **Strings Detail** — chaînes extraites (URLs, IPs, registres)
- **ClamAV Panel** — statut base + mise à jour (avec progression)
- **Settings Panel** — clé API VT, chemin base ClamAV
- **Export Menu** — JSON, HTML, TXT, Markdown, PDF

---

## 🚀 Installation

Télécharger `FileScanner_<version>_x64-setup.exe` depuis les [Releases](../../releases).

L'installation se fait pour l'utilisateur courant, sans élévation. Une seule
entrée apparaît dans la liste des applications de Windows, et la désinstaller
la retire entièrement.

Les mises à jour suivantes se font toutes seules depuis l'application.

> Sous Linux, la CI produit des paquets `.deb`, `.rpm` et `.AppImage`.

---

## ⚙️ Configuration

### VirusTotal (optionnel)
1. Créer un compte gratuit sur [virustotal.com](https://www.virustotal.com)
2. Obtenir une clé API (quota : 500 req/jour gratuit)
3. Renseigner dans **Settings** → *VirusTotal API Key*

> ⚠️ La clé API est stockée dans le **Windows Credential Manager** — jamais en
> clair sur le disque. Elle est aussi purgée de la RAM après chaque scan.

### ClamAV (optionnel, améliore la détection)
- Installer [ClamAV pour Windows](https://www.clamav.net/downloads)
- Ou laisser l'application télécharger automatiquement les bases (auto-update 24h)

---

## 🏗️ Build depuis les sources

### Prérequis
- [Node.js](https://nodejs.org) ≥ 18
- [Rust](https://rustup.rs) stable
- [Tauri CLI v2](https://tauri.app)

```bash
git clone https://github.com/Heiphaistos/FileScanner-AppWindows.git
cd FileScanner-AppWindows

npm install
npm run tauri dev     # développement
npx tauri build       # build de production
```

Binaires dans `src-tauri/target/release/bundle/`.

### Publier une version

Le build doit être signé, sinon le manifeste de mise à jour ne vaut rien :

```bash
export TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.tauri/filescanner-updater.key)"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""
npx tauri build
python outils/publier.py --notes "Ce qui change pour l'utilisateur."
```

`publier.py` fabrique le manifeste signé et le téléverse avec l'installeur.

> ⚠️ Sans la clé privée, les applications déjà installées refuseront toute
> mise à jour : la clé publique correspondante est gravée dans leur binaire.

---

## 🗂️ Architecture

```
FileScanner-AppWindows/
├── src/                       # Frontend Vue 3 + TypeScript
│   ├── components/            # DropZone, VerdictDisplay, IoC Table, PE Details…
│   ├── composables/
│   │   └── useAutoUpdate.ts   # Vérification et installation des mises à jour
│   ├── stores/                # Pinia state management
│   └── types/                 # Types partagés
├── outils/
│   └── publier.py             # Manifeste signé + téléversement du canal
├── src-tauri/                 # Backend Rust
│   ├── tauri.windows.conf.json   # Windows : NSIS uniquement
│   ├── README-bundles.md         # Pourquoi deux fichiers de configuration
│   └── src/
│       ├── analyzer/          # hash, MIME, PE parser, script parser, entropie
│       ├── scanner/           # Pipeline + YARA engine + ClamAV DB
│       ├── api/               # VirusTotal API client (backoff exponentiel)
│       ├── background/        # Worker auto-update ClamAV
│       ├── commands_extra/    # Quarantaine fichier
│       ├── ai/                # Inférence locale (heuristique)
│       ├── report/            # Export JSON/HTML/TXT/MD/PDF (XSS-safe)
│       └── config/            # Settings (keyring) + ClamAV updater
```

---

## 🔒 Sécurité & Confidentialité

- **Hors-ligne par défaut** — aucune donnée envoyée sans action explicite
- **VirusTotal** — uniquement le **hash** du fichier est envoyé, jamais le fichier
- **Clé API** — Windows Credential Manager, purgée de la RAM après scan
- **YARA** — analyse entièrement locale
- **Path traversal** — chemins canonicalisés et vérifiés avant tout traitement
- **Quarantaine** — chiffrement XOR : le fichier devient inopérant sans être détruit
- **Mises à jour** — manifeste et installeur signés, vérifiés avant installation

La seule requête sortante hors VirusTotal est la vérification de mise à jour,
qui ne transmet aucune donnée sur les fichiers analysés.

---

## 📄 Licence

MIT — voir [LICENSE](LICENSE)

---

## 👤 Crédits

Développé par **[Heiphaistos](https://heiphaistos.org)**.

Bibliothèques principales : [Tauri v2](https://tauri.app), [Vue 3](https://vuejs.org),
[YARA-X](https://virustotal.github.io/yara-x/), [ClamAV](https://www.clamav.net),
[goblin](https://github.com/m4b/goblin) (parsing PE), [printpdf](https://github.com/fschutt/printpdf).

Bases de signatures : [ClamAV](https://www.clamav.net) (GPL-2.0).
Données de réputation : [VirusTotal](https://www.virustotal.com) (API publique).
