use crate::report::types::{Severity, YaraMatch};
use crate::{sig, sig_bytes, txt};

struct Rule {
    name: &'static str,
    description: &'static str,
    severity: Severity,
    patterns: Vec<Pattern>,
    require_all: bool,
}

enum Pattern {
    Bytes(Vec<u8>),
    StringInsensitive(String),
}

/// Motif texte insensible à la casse, stocké inversé dans le binaire (cf. `obf`).
fn ps(reversed: &[u8]) -> Pattern {
    Pattern::StringInsensitive(crate::obf::restore_str(reversed))
}

/// Motif d'octets, stocké inversé dans le binaire (cf. `obf`).
fn pb(reversed: &[u8]) -> Pattern {
    Pattern::Bytes(crate::obf::restore(reversed))
}

/// `word_start` : pour les règles qui cherchent un NOM (famille de malware, outil), le
/// nom doit commencer un mot. Sans cela « formbook » sortait du dictionnaire Brotli
/// embarqué par d'innombrables programmes (« …loveformbookplay… »).
fn match_pattern_desc(data: &[u8], lower_data: &[u8], pattern: &Pattern, word_start: bool) -> Option<String> {
    match pattern {
        Pattern::Bytes(needle) => {
            if data.windows(needle.len()).any(|w| w == needle.as_slice()) {
                let desc = if needle.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                    format!("\"{}\"", std::str::from_utf8(needle).unwrap_or("?"))
                } else {
                    format!(
                        "hex: {}",
                        needle.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
                    )
                };
                Some(desc)
            } else {
                None
            }
        }
        Pattern::StringInsensitive(s) => {
            let needle = s.to_lowercase();
            let n = needle.as_bytes();
            let guard = word_start && n.first().is_some_and(|b| b.is_ascii_alphanumeric());
            // Extension (« .conti ») : elle doit aussi FINIR le mot, sinon toute phrase
            // française collée à la suivante (« …comportement.Contient… ») déclenche.
            let end_guard = word_start && n.first() == Some(&b'.');
            let found = lower_data.windows(n.len()).enumerate().any(|(i, w)| {
                w == n
                    && !(guard && i > 0 && lower_data[i - 1].is_ascii_alphanumeric())
                    && !(end_guard && lower_data.get(i + n.len()).is_some_and(|b| b.is_ascii_alphanumeric()))
            });
            if found {
                Some(format!("\"{}\"", s))
            } else {
                None
            }
        }
    }
}

fn build_rules() -> Vec<Rule> {
    vec![
        // Fichier de test antivirus : inoffensif, mais détecté par convention.
        Rule {
            name: "EICAR_Test_File",
            description: txt!("Fichier de test antivirus EICAR (inoffensif, détecté par convention)"),
            severity: Severity::Critical,
            patterns: vec![pb(sig_bytes!(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"))],
            require_all: false,
        },
        Rule {
            name: "UPX_Packer",
            description: txt!("Packer UPX détecté (compression PE)"),
            severity: Severity::Medium,
            patterns: vec![pb(sig_bytes!(b"UPX0")), pb(sig_bytes!(b"UPX!"))],
            require_all: false,
        },
        Rule {
            name: "MPRESS_Packer",
            description: txt!("Packer MPRESS détecté"),
            severity: Severity::Medium,
            patterns: vec![pb(sig_bytes!(b"MPRESS1"))],
            require_all: false,
        },
        Rule {
            name: "Ransomware_Strings",
            description: txt!("Chaînes caractéristiques de ransomware (message victime)"),
            severity: Severity::Critical,
            // require_all:true — les 2 strings doivent coexister pour éviter FP sur outils sécu
            patterns: vec![
                ps(sig!("your files have been encrypted")),
                ps(sig!("decrypt your files")),
            ],
            require_all: true,
        },
        Rule {
            name: "Ransomware_Payment",
            description: txt!("Instructions paiement ransom (BTC + Tor)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("bitcoin")),
                ps(sig!("tor browser")),
            ],
            require_all: true,
        },
        Rule {
            name: "Process_Injection",
            description: txt!("Signatures d'injection de processus (CreateRemoteThread)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("createremotethread")),
                ps(sig!("virtualallocex")),
            ],
            require_all: true,
        },
        Rule {
            name: "Keylogger_Strings",
            description: txt!("APIs capture clavier (GetAsyncKeyState + GetKeyboardState)"),
            // Medium — les 2 APIs coexistent dans WebView2/Chromium = FP pour apps Tauri
            severity: Severity::Medium,
            patterns: vec![
                ps(sig!("getasynckeystate")),
                ps(sig!("getkeyboardstate")),
            ],
            require_all: true,
        },
        Rule {
            name: "Network_Downloader",
            description: txt!("Téléchargement réseau suspect (URLDownloadToFile)"),
            severity: Severity::High,
            patterns: vec![ps(sig!("urldownloadtofile"))],
            require_all: false,
        },
        Rule {
            name: "Mimikatz_Strings",
            description: txt!("Signatures de l'outil de vol de credentials Mimikatz"),
            severity: Severity::Critical,
            patterns: vec![
                pb(sig_bytes!(b"mimikatz")),
                pb(sig_bytes!(b"sekurlsa")),
                ps(sig!("lsadump")),
            ],
            require_all: false,
        },
        Rule {
            name: "AntiDebug_Techniques",
            description: txt!("Anti-debug actif : IsDebuggerPresent + NtQueryInformationProcess"),
            severity: Severity::High,
            // require_all:true — IsDebuggerPresent seul = FP (Tauri, .NET, tout framework)
            patterns: vec![
                ps(sig!("isdebuggerpresent")),
                ps(sig!("checkremotedebuggerpresent")),
            ],
            require_all: true,
        },
        Rule {
            name: "Persistence_Registry",
            description: txt!("Accès clés de démarrage du registre"),
            // Medium — outils diagnostic accèdent légitimement à ces clés
            severity: Severity::Medium,
            patterns: vec![
                ps(sig!("software\\microsoft\\windows\\currentversion\\run")),
                ps(sig!("software\\microsoft\\windows nt\\currentversion\\winlogon")),
            ],
            require_all: false,
        },
        Rule {
            name: "Shellcode_Patterns",
            description: txt!("NOP sled extrême (64+ bytes) — shellcode probable"),
            severity: Severity::High,
            // 32 NOPs = encore FP dans .rdata/assets Tauri bundlés. 64 NOPs = vraiment anormal.
            // Un NOP sled légitime (alignement compilateur) dépasse rarement 16 bytes.
            // Généré à l'exécution : un littéral de 64 NOP déclenchait la règle sur notre exe.
            patterns: vec![Pattern::Bytes(vec![0x90; 64])],
            require_all: true,
        },
        Rule {
            name: "PowerShell_Encoded_Cmd",
            description: txt!("Commande PowerShell encodée (-EncodedCommand)"),
            // Medium — outils diagnostic/admin utilisent légitimement -encodedcommand
            severity: Severity::Medium,
            patterns: vec![
                ps(sig!("powershell")),
                ps(sig!("-encodedcommand")),
            ],
            require_all: true,
        },
        Rule {
            name: "Suspicious_Certutil",
            description: txt!("Utilisation de certutil pour decode/téléchargement"),
            severity: Severity::High,
            patterns: vec![
                ps(sig!("certutil")),
                ps(sig!("-decode")),
            ],
            require_all: true,
        },
        // ── Ransomware — familles modernes ────────────────────────────────────
        Rule {
            name: "Ransomware_Modern_Families",
            description: txt!("Noms de familles ransomware connues (LockBit, Conti, BlackCat, REvil…)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("lockbit")),
                ps(sig!("blackcat")),
                ps(sig!("alphv")),
                ps(sig!("revil")),
                ps(sig!("ryuk ransomware")),
                ps(sig!("hive ransomware")),
                ps(sig!("blackbasta")),
            ],
            require_all: false,
        },
        Rule {
            name: "Ransomware_Extensions",
            description: txt!("Extensions de chiffrement ransomware spécifiques"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!(".lockbit")),
                ps(sig!(".conti")),
                ps(sig!(".ryk")),
                ps(sig!(".blackcat")),
            ],
            require_all: false,
        },
        // ── Stealers ──────────────────────────────────────────────────────────
        Rule {
            name: "Stealer_Modern_Families",
            description: txt!("Infostealers connus (RedLine, Raccoon, Vidar, Lumma, AgentTesla, FormBook)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("redline stealer")),
                ps(sig!("raccoon stealer")),
                ps(sig!("vidar")),
                ps(sig!("lumma")),
                ps(sig!("agenttesla")),
                ps(sig!("formbook")),
                ps(sig!("redlinestealer")),
            ],
            require_all: false,
        },
        Rule {
            name: "Discord_Webhook_Exfil",
            description: txt!("Exfiltration via webhook Discord (vol de données)"),
            severity: Severity::High,
            patterns: vec![
                ps(sig!("discord.com/api/webhooks/")),
                ps(sig!("discordapp.com/api/webhooks/")),
            ],
            require_all: false,
        },
        // ── Injection / évasion (parité avec version web) ─────────────────────
        Rule {
            name: "Process_Hollowing",
            description: txt!("Process hollowing (NtUnmapViewOfSection + ResumeThread)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("ntunmapviewofsection")),
                ps(sig!("resumethread")),
            ],
            require_all: true,
        },
        Rule {
            name: "AMSI_Bypass",
            description: txt!("Bypass AMSI (antimalware scan interface)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("amsiutils")),
                ps(sig!("amsiinitfailed")),
                ps(sig!("amsiscanbuffer")),
            ],
            require_all: false,
        },
        Rule {
            name: "Defender_Tampering",
            description: txt!("Désactivation de Windows Defender"),
            severity: Severity::Critical,
            patterns: vec![ps(sig!("set-mppreference -disablerealtimemonitoring"))],
            require_all: false,
        },
        Rule {
            name: "PHP_Webshell",
            description: txt!("Webshell PHP (eval + entrée utilisateur)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("eval($_post")),
                ps(sig!("eval($_get")),
                ps(sig!("eval(base64_decode")),
            ],
            require_all: false,
        },
        Rule {
            name: "Bash_Reverse_Shell",
            description: txt!("Reverse shell bash (/dev/tcp)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("/dev/tcp/")),
                ps(sig!("bash -i")),
            ],
            require_all: true,
        },
        Rule {
            name: "CobaltStrike_Beacon",
            description: txt!("Signatures Cobalt Strike Beacon"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("beacon.dll")),
                ps(sig!("reflectiveloader@4")),
            ],
            require_all: false,
        },
        Rule {
            name: "Common_RAT_Strings",
            description: txt!("Signatures de RATs courants (njRAT, AsyncRAT, QuasarRAT, Remcos)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("njrat")),
                ps(sig!("asyncrat")),
                ps(sig!("quasar.client")),
                ps(sig!("remcos")),
                ps(sig!("nanocore")),
            ],
            require_all: false,
        },
        Rule {
            name: "CryptoMiner_Strings",
            description: txt!("Mineur de cryptomonnaie embarqué"),
            severity: Severity::High,
            patterns: vec![
                ps(sig!("stratum+tcp://")),
                ps(sig!("xmrig")),
                ps(sig!("cryptonight")),
                ps(sig!("--donate-level")),
            ],
            require_all: false,
        },
        // ── UAC bypass ────────────────────────────────────────────────────────
        Rule {
            name: "UAC_Bypass_Techniques",
            description: txt!("Bypass UAC connu (fodhelper, eventvwr, sdclt, computerdefaults, silentcleanup)"),
            severity: Severity::High,
            patterns: vec![
                ps(sig!("fodhelper.exe")),
                ps(sig!("computerdefaults.exe")),
                ps(sig!("sdclt.exe")),
                ps(sig!("silentcleanup")),
            ],
            require_all: false,
        },
        // ── Macros Office ─────────────────────────────────────────────────────
        Rule {
            name: "Office_Macro_AutoExec",
            description: txt!("Macro Office à exécution automatique (AutoOpen, Workbook_Open)"),
            severity: Severity::High,
            patterns: vec![
                ps(sig!("autoopen")),
                ps(sig!("auto_open")),
                ps(sig!("workbook_open")),
                ps(sig!("document_open")),
            ],
            require_all: false,
        },
        // ── Loaders / droppers connus ─────────────────────────────────────────
        Rule {
            name: "Malware_Loader_Families",
            description: txt!("Loaders/droppers connus (Emotet, QakBot, IcedID, Bumblebee, Gozi)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("emotet")),
                ps(sig!("qakbot")),
                ps(sig!("qbot")),
                ps(sig!("icedid")),
                ps(sig!("bumblebee loader")),
                ps(sig!("gozi")),
                ps(sig!("bazarloader")),
            ],
            require_all: false,
        },
        // ── APT / implants ciblés ─────────────────────────────────────────────
        Rule {
            name: "APT_Implant_Families",
            description: txt!("Implants APT connus (PlugX, Winnti, ShadowPad, Sakula, Gh0st RAT)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("plugx")),
                ps(sig!("winnti")),
                ps(sig!("shadowpad")),
                ps(sig!("sakula")),
                ps(sig!("gh0st rat")),
                ps(sig!("poisonivy")),
            ],
            require_all: false,
        },
        // ── Macro Excel 4.0 (XLM) ─────────────────────────────────────────────
        Rule {
            name: "Office_XLM4_Macro",
            description: txt!("Macro Excel 4.0 (XLM) à primitives d'exécution (=EXEC/=CALL/=REGISTER)"),
            severity: Severity::High,
            patterns: vec![
                ps(sig!("=exec(")),
                ps(sig!("=call(")),
                ps(sig!("=register(")),
            ],
            require_all: false,
        },
        // ── HTA embarqué ──────────────────────────────────────────────────────
        Rule {
            name: "HTA_Application",
            description: txt!("Application HTA (HTML Application) — vecteur d'exécution de script"),
            severity: Severity::High,
            patterns: vec![ps(sig!("<hta:application"))],
            require_all: false,
        },
        // ── Credential dumping LSASS ──────────────────────────────────────────
        Rule {
            name: "LSASS_Credential_Dumping",
            description: txt!("Outils de dump LSASS sans ambiguïté (nanodump, dumpert, SafetyKatz, sekurlsa::minidump)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("nanodump")),
                ps(sig!("dumpert")),
                ps(sig!("safetykatz")),
                ps(sig!("sekurlsa::minidump")),
                ps(sig!("lsass.dmp")),
            ],
            require_all: false,
        },
        // ── Packers additionnels (sections PE) ────────────────────────────────
        Rule {
            name: "Additional_Packers",
            description: txt!("Packers/protecteurs additionnels (Themida, Enigma, Obsidium)"),
            severity: Severity::Medium,
            patterns: vec![
                pb(sig_bytes!(b".themida")),
                pb(sig_bytes!(b".enigma1")),
                pb(sig_bytes!(b".enigma2")),
                pb(sig_bytes!(b"Obsidium")),
            ],
            require_all: false,
        },
        // ── Loaders/droppers additionnels ─────────────────────────────────────
        Rule {
            name: "Loader_Families_2",
            description: txt!("Loaders récents (GuLoader, SmokeLoader, DBatLoader, PrivateLoader)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("guloader")),
                ps(sig!("smokeloader")),
                ps(sig!("dbatloader")),
                ps(sig!("privateloader")),
                ps(sig!("modiloader")),
            ],
            require_all: false,
        },
        // ── Mouvement latéral (outils Impacket) ───────────────────────────────
        Rule {
            name: "Impacket_Lateral_Movement",
            description: txt!("Outils Impacket d'exécution distante (wmiexec, smbexec, psexec.py, atexec, dcomexec)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("wmiexec")),
                ps(sig!("smbexec")),
                ps(sig!("psexec.py")),
                ps(sig!("atexec")),
                ps(sig!("dcomexec")),
                ps(sig!("secretsdump")),
            ],
            require_all: false,
        },
        // ── Outils d'attaque Active Directory ─────────────────────────────────
        Rule {
            name: "AD_Attack_Tools",
            description: txt!("Outils offensifs Active Directory (Rubeus, Kerberoast, SharpHound, Certify)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("rubeus")),
                ps(sig!("kerberoast")),
                ps(sig!("asreproast")),
                ps(sig!("sharphound")),
                ps(sig!("certify.exe")),
                ps(sig!("getuserspns")),
            ],
            require_all: false,
        },
        // ── Mineurs GPU (extension cryptominer) ───────────────────────────────
        Rule {
            name: "GPU_Miner_Binaries",
            description: txt!("Mineurs GPU connus (NBMiner, PhoenixMiner, lolMiner, T-Rex, GMiner, TeamRedMiner)"),
            severity: Severity::High,
            patterns: vec![
                ps(sig!("nbminer")),
                ps(sig!("phoenixminer")),
                ps(sig!("lolminer")),
                ps(sig!("t-rex miner")),
                ps(sig!("gminer")),
                ps(sig!("teamredminer")),
            ],
            require_all: false,
        },
        // ── Frameworks C2 / post-exploitation additionnels ────────────────────
        Rule {
            name: "C2_PostEx_Frameworks",
            description: txt!("Frameworks C2 / post-exploitation (PoshC2, Covenant, Empire, Merlin, Villain)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("poshc2")),
                ps(sig!("covenant grunt")),
                ps(sig!("empire agent")),
                ps(sig!("merlin agent")),
                ps(sig!("villain c2")),
                ps(sig!("posh_v4")),
            ],
            require_all: false,
        },
        // ── RATs additionnels (familles commerciales/crimeware) ───────────────
        Rule {
            name: "RAT_Families_2",
            description: txt!("RATs additionnels (Warzone/Ave Maria, NetWire, Orcus, VenomRAT, XWorm, DarkComet)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("warzone rat")),
                ps(sig!("ave_maria")),
                ps(sig!("netwire")),
                ps(sig!("orcus rat")),
                ps(sig!("venomrat")),
                ps(sig!("xworm")),
                ps(sig!("darkcomet")),
            ],
            require_all: false,
        },
        // ── Wipers (destruction de données) ───────────────────────────────────
        Rule {
            name: "Wiper_Families",
            description: txt!("Malwares destructifs (WhisperGate, HermeticWiper, CaddyWiper, KillDisk, Shamoon)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("whispergate")),
                ps(sig!("hermeticwiper")),
                ps(sig!("caddywiper")),
                ps(sig!("killdisk")),
                ps(sig!("shamoon")),
                ps(sig!("isaacwiper")),
            ],
            require_all: false,
        },
        // ── Stealers modernes (crimeware 2023+) ───────────────────────────────
        Rule {
            name: "Stealer_Families_3",
            description: txt!("Infostealers récents (Rhadamanthys, StealC, Meduza, RisePro, Atomic/AMOS)"),
            severity: Severity::Critical,
            patterns: vec![
                ps(sig!("rhadamanthys")),
                ps(sig!("stealc")),
                ps(sig!("meduza stealer")),
                ps(sig!("risepro")),
                ps(sig!("atomic stealer")),
                ps(sig!("amos stealer")),
            ],
            require_all: false,
        },
    ]
}

pub struct YaraEngine {
    rules: Vec<Rule>,
}

impl YaraEngine {
    pub fn new() -> Self {
        Self {
            rules: build_rules(),
        }
    }

    pub fn scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        // Pré-calcul lowercase une seule fois (vs 1x par pattern auparavant)
        let lower_data: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();

        let mut matches = Vec::new();

        for rule in &self.rules {
            let word_start = crate::assessment::is_mention_rule(rule.name);
            let matched_strings: Vec<String> = rule
                .patterns
                .iter()
                .filter_map(|p| match_pattern_desc(data, &lower_data, p, word_start))
                .collect();

            let triggered = if rule.require_all {
                matched_strings.len() == rule.patterns.len()
            } else {
                !matched_strings.is_empty()
            };

            if triggered {
                matches.push(YaraMatch {
                    rule_name: rule.name.to_string(),
                    description: rule.description.to_string(),
                    severity: rule.severity.clone(),
                    matched_strings,
                });
            }
        }

        matches
    }
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::YaraEngine;

    /// Écrit à l'envers dans le source, comme les règles (cf. `obf`).
    fn rev(s: &str) -> Vec<u8> {
        s.bytes().rev().collect()
    }

    fn rules(data: &[u8]) -> Vec<String> {
        YaraEngine::new().scan(data).into_iter().map(|m| m.rule_name).collect()
    }

    #[test]
    fn nom_de_famille_colle_dans_un_dictionnaire_ignore() {
        // Extrait réel du dictionnaire Brotli embarqué par PureRGB.
        let dico = rev("yalpkoobmrofevolydobrevoraey");
        assert!(!rules(&dico).contains(&"Stealer_Modern_Families".to_string()));
    }

    #[test]
    fn nom_de_famille_isole_toujours_detecte() {
        for s in ["\0koobmroF\0", " 2CammuL", "\"radiV\""] {
            assert!(rules(&rev(s)).contains(&"Stealer_Modern_Families".to_string()), "{s}");
        }
    }

    #[test]
    fn extension_doit_finir_le_mot() {
        let ext = "Ransomware_Extensions".to_string();
        assert!(!rules(&rev("tneitnoC.tnemetropmoc")).contains(&ext));
        assert!(rules(&rev("\0itnoc.txt.erutcaf")).contains(&ext));
    }

    /// Anti-régression : l'exe livré ne contient aucun motif de détection en clair (sinon
    /// FileScanner se classe lui-même malveillant ; LLVM y repliait même des constantes,
    /// « mimikatz » ressortait en clair). Vérifie l'exe release s'il a été construit : le
    /// binaire de test, lui, embarque des échantillons. Seule tolérée : Keylogger_Strings,
    /// déclenchée par les VRAIS imports de WebView/tao.
    #[test]
    fn notre_binaire_ne_declenche_aucune_regle() {
        let release = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/release")
            .join(if cfg!(windows) { "file-scanner.exe" } else { "file-scanner" });
        let bins: Vec<_> = release.exists().then_some(release).into_iter().collect();
        if bins.is_empty() {
            eprintln!("exe release absent : construire avant de tester (cargo build --release)");
        }
        for bin in bins {
            let hits: Vec<_> = YaraEngine::new()
                .scan(&std::fs::read(&bin).unwrap())
                .into_iter()
                .filter(|m| m.rule_name != "Keylogger_Strings")
                .map(|m| format!("{} {:?}", m.rule_name, m.matched_strings))
                .collect();
            assert!(hits.is_empty(), "{} : {hits:?}", bin.display());
        }
    }
}
