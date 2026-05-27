# 🔍 FileScanner v1.0.0

> Analyseur de sécurité de fichiers — Desktop app Windows (Tauri v2 + Rust + Vue 3)

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Version](https://img.shields.io/badge/version-1.0.0-green)
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
| 🦠 **ClamAV** | Lookup MD5/SHA256 dans base locale ClamAV |
| 🌐 **VirusTotal** | Lookup hash via API VT (clé optionnelle) |
| 📊 **Export** | JSON, HTML, TXT, Markdown, PDF |
| 🎯 **Verdict** | Propre / Suspect / Malveillant avec score de confiance |

---

## 📸 Interface

- **Drop Zone** — glisser-déposer un fichier
- **Verdict Display** — résumé visuel du verdict
- **IoC Table** — liste des indicateurs de compromission détectés
- **PE Details** — détails binaires des exécutables Windows
- **Strings Detail** — chaînes extraites (URLs, IPs, registres)
- **ClamAV Panel** — statut base + mise à jour
- **Settings Panel** — clé API VT, chemin base ClamAV

---

## 🚀 Installation

### Option 1 — Installeur (recommandé)
Télécharger `FileScanner_1.0.0_x64-setup.exe` depuis les [Releases](../../releases).

### Option 2 — MSI
Télécharger `FileScanner_1.0.0_x64_en-US.msi` depuis les [Releases](../../releases).

---

## ⚙️ Configuration

### VirusTotal (optionnel)
1. Créer un compte gratuit sur [virustotal.com](https://www.virustotal.com)
2. Obtenir une clé API (quota : 500 req/jour)
3. Renseigner dans **Settings** → *VirusTotal API Key*

> ⚠️ La clé API n'est jamais committée — elle est stockée localement dans les settings de l'app.

### ClamAV (optionnel, améliore la détection)
- Installer [ClamAV pour Windows](https://www.clamav.net/downloads)
- Ou renseigner le chemin d'une base `.cvd`/`.cld` dans Settings

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
├── src/                    # Frontend Vue 3 + TypeScript
│   ├── components/         # DropZone, VerdictDisplay, IoC Table, PE Details…
│   ├── stores/             # Pinia state management
│   └── types/              # Types partagés
├── src-tauri/              # Backend Rust
│   └── src/
│       ├── analyzer/       # hash, MIME, PE parser, script parser, entropie
│       ├── scanner/        # Pipeline + YARA engine + ClamAV DB
│       ├── api/            # VirusTotal API client
│       ├── ai/             # Inférence locale (heuristique)
│       ├── report/         # Export JSON/HTML/TXT/MD/PDF
│       └── config/         # Settings + ClamAV updater
└── clamav-1.5.2.win.x64/  # Binaires ClamAV (facultatif)
```

---

## 🔒 Sécurité & Confidentialité

- **Hors-ligne par défaut** — aucune donnée envoyée sans action explicite
- **VirusTotal** — uniquement le **hash** du fichier est envoyé (jamais le fichier lui-même)
- **Clé API** — stockée localement, jamais en clair dans le code
- **YARA** — analyse entièrement locale

---

## 📄 Licence

MIT — voir [LICENSE](LICENSE)

---

*Développé par [Heiphaistos](https://heiphaistos.org)*
