# 🔍 FileScanner v1.1.0

> Analyseur de sécurité de fichiers — Desktop app Windows (Tauri v2 + Rust + Vue 3)

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Version](https://img.shields.io/badge/version-1.1.0-green)
![Stack](https://img.shields.io/badge/stack-Tauri%20v2%20%7C%20Rust%20%7C%20Vue%203-orange)

---

## ✨ Fonctionnalités

| Module | Description |
|--------|-------------|
| 🔑 **Hash** | MD5, SHA256, SHA1 — streaming sur fichiers volumineux |
| 🧬 **MIME réel** | Détection type réel (bypass extension falsifiée) |
| 🪟 **Analyse PE** | Headers, imports, sections, anomalies binaires |
| 📜 **Scripts** | Analyse PowerShell, Batch, VBS, JS — IoCs & obfuscation |
| 🛡️ **YARA** | 50+ règles intégrées — détection heuristique |
| 🦠 **ClamAV** | Lookup MD5/SHA256 dans base locale ClamAV + **auto-update 24h** |
| 🌐 **VirusTotal** | Lookup hash via API VT — **backoff exponentiel 429** |
| 📊 **Export** | JSON, HTML (XSS-safe), TXT, Markdown, PDF |
| 🎯 **Verdict** | Propre / Suspect / Malveillant avec score de confiance |
| 🔒 **Quarantaine** | Neutralisation + déplacement sécurisé des fichiers malveillants |

---

## 🔐 Sécurité — Nouveautés v1.1.0

| Fix | Sévérité | Description |
|-----|----------|-------------|
| Path Traversal | 🔴 CRITIQUE | Validation stricte des chemins entrants — séquences `..` bloquées |
| Export path injection | 🔴 CRITIQUE | Chemin de destination d'export validé avant écriture |
| Scan timeout | 🟡 MOYENNE | Timeout global de 2 minutes par analyse |
| Regex `.expect()` → `LazyLock` | 🟠 HAUTE | Pré-compilation des regexes — plus de panic potentielle |
| VT backoff exponentiel | 🟠 HAUTE | 3 tentatives × 2^n×500ms sur erreur 429 / timeout |
| API key RAM purge | 🟠 HAUTE | Clé VT effacée du store Pinia après chaque scan |
| CVD bomb protection | 🟡 MOYENNE | Limite 500 MB sur les fichiers CVD avant extraction |
| HTML export XSS | 🟡 MOYENNE | HTML-escape sur toutes les strings dans les rapports |

---

## 🆕 Nouvelles fonctionnalités v1.1.0

### 🔒 Quarantaine
Bouton visible uniquement si le verdict est **MALVEILLANT**.
- Chiffrement XOR du fichier (neutralise l'exécution)
- Déplacement vers `%APPDATA%\FileScanner\quarantine\{sha256}.quar`
- Métadonnées JSON : chemin original, date, taille
- Suppression du fichier source

### 🔄 Mise à jour automatique ClamAV
Worker tokio en arrière-plan au démarrage :
- Vérifie si `daily.cvd` est périmé (> 24h)
- Télécharge silencieusement si nécessaire
- Émet des événements de progression vers l'UI (`clamav://update-progress`)

### ⚡ Virtual Scrolling IoC Table
Activé automatiquement si > 100 indicateurs :
- Rendu uniquement de la fenêtre visible (12 lignes)
- DOM constant quelle que soit la quantité d'IoCs
- Indicateur visuel « scroll virtuel »

---

## 📸 Interface

- **Drop Zone** — glisser-déposer un fichier
- **Verdict Display** — résumé visuel + bouton quarantaine (si malveillant)
- **IoC Table** — liste paginée virtuellement
- **PE Details** — détails binaires des exécutables Windows
- **Strings Detail** — chaînes extraites (URLs, IPs, registres)
- **ClamAV Panel** — statut base + mise à jour (avec progression)
- **Settings Panel** — clé API VT, chemin base ClamAV

---

## 🚀 Installation

### Option 1 — Installeur (recommandé)
Télécharger `FileScanner_1.1.0_x64-setup.exe` depuis les [Releases](../../releases).

### Option 2 — MSI
Télécharger `FileScanner_1.1.0_x64_en-US.msi` depuis les [Releases](../../releases).

### Option 3 — Portable
Télécharger `FileScanner_1.1.0_x64_portable.zip` — extraire et lancer `FileScanner.exe`.

---

## ⚙️ Configuration

### VirusTotal (optionnel)
1. Créer un compte gratuit sur [virustotal.com](https://www.virustotal.com)
2. Obtenir une clé API (quota : 500 req/jour gratuit)
3. Renseigner dans **Settings** → *VirusTotal API Key*

> ⚠️ La clé API est stockée dans le **Windows Credential Manager** — jamais en clair sur le disque.  
> Elle est aussi purgée de la RAM après chaque scan (v1.1.0).

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
# Cloner
git clone https://github.com/heiphaistos44-crypto/FileScanner.git
cd FileScanner

# Installer dépendances JS
npm install

# Dev
npm run tauri dev

# Build prod
npx tauri build
```

Binaires dans `src-tauri/target/release/bundle/`.

---

## 🗂️ Architecture

```
FileScanner/
├── src/                       # Frontend Vue 3 + TypeScript
│   ├── components/            # DropZone, VerdictDisplay, IoC Table, PE Details…
│   │   └── QuarantineButton.vue  # ← NOUVEAU v1.1.0
│   ├── stores/                # Pinia state management
│   └── types/                 # Types partagés
├── src-tauri/                 # Backend Rust
│   └── src/
│       ├── analyzer/          # hash, MIME, PE parser, script parser, entropie
│       ├── scanner/           # Pipeline + YARA engine + ClamAV DB
│       ├── api/               # VirusTotal API client (backoff exponentiel)
│       ├── background/        # ← NOUVEAU — Worker auto-update ClamAV
│       ├── commands_extra/    # ← NOUVEAU — Quarantaine fichier
│       ├── ai/                # Inférence locale (heuristique)
│       ├── report/            # Export JSON/HTML/TXT/MD/PDF (XSS-safe)
│       └── config/            # Settings (keyring) + ClamAV updater
```

---

## 🔒 Sécurité & Confidentialité

- **Hors-ligne par défaut** — aucune donnée envoyée sans action explicite
- **VirusTotal** — uniquement le **hash** du fichier est envoyé (jamais le fichier lui-même)
- **Clé API** — stockée dans le Windows Credential Manager, purgée de la RAM post-scan
- **YARA** — analyse entièrement locale
- **Path traversal** — chemins validés et canonicalisés avant tout traitement
- **Quarantaine** — XOR-chiffrement rend le fichier inopérant sans le détruire

---

## 📄 Licence

MIT — voir [LICENSE](LICENSE)

---

*Développé par [Heiphaistos](https://heiphaistos.org)*
