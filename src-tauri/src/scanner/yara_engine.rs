use crate::report::types::{Severity, YaraMatch};

struct Rule {
    name: &'static str,
    description: &'static str,
    severity: Severity,
    patterns: Vec<Pattern>,
    require_all: bool,
}

enum Pattern {
    Bytes(&'static [u8]),
    StringInsensitive(&'static str),
}

fn match_pattern_desc(data: &[u8], lower_data: &[u8], pattern: &Pattern) -> Option<String> {
    match pattern {
        Pattern::Bytes(needle) => {
            if data.windows(needle.len()).any(|w| w == *needle) {
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
            if lower_data.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                Some(format!("\"{}\"", s))
            } else {
                None
            }
        }
    }
}

fn build_rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "UPX_Packer",
            description: "Packer UPX détecté (compression PE)",
            severity: Severity::Medium,
            patterns: vec![Pattern::Bytes(b"UPX0"), Pattern::Bytes(b"UPX!")],
            require_all: false,
        },
        Rule {
            name: "MPRESS_Packer",
            description: "Packer MPRESS détecté",
            severity: Severity::Medium,
            patterns: vec![Pattern::Bytes(b"MPRESS1")],
            require_all: false,
        },
        Rule {
            name: "Ransomware_Strings",
            description: "Chaînes caractéristiques de ransomware (message victime)",
            severity: Severity::Critical,
            // require_all:true — les 2 strings doivent coexister pour éviter FP sur outils sécu
            patterns: vec![
                Pattern::StringInsensitive("your files have been encrypted"),
                Pattern::StringInsensitive("decrypt your files"),
            ],
            require_all: true,
        },
        Rule {
            name: "Ransomware_Payment",
            description: "Instructions paiement ransom (BTC + Tor)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("bitcoin"),
                Pattern::StringInsensitive("tor browser"),
            ],
            require_all: true,
        },
        Rule {
            name: "Process_Injection",
            description: "Signatures d'injection de processus (CreateRemoteThread)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("createremotethread"),
                Pattern::StringInsensitive("virtualallocex"),
            ],
            require_all: true,
        },
        Rule {
            name: "Keylogger_Strings",
            description: "APIs capture clavier (GetAsyncKeyState + GetKeyboardState)",
            // Medium — les 2 APIs coexistent dans WebView2/Chromium = FP pour apps Tauri
            severity: Severity::Medium,
            patterns: vec![
                Pattern::StringInsensitive("getasynckeystate"),
                Pattern::StringInsensitive("getkeyboardstate"),
            ],
            require_all: true,
        },
        Rule {
            name: "Network_Downloader",
            description: "Téléchargement réseau suspect (URLDownloadToFile)",
            severity: Severity::High,
            patterns: vec![Pattern::StringInsensitive("urldownloadtofile")],
            require_all: false,
        },
        Rule {
            name: "Mimikatz_Strings",
            description: "Signatures de l'outil de vol de credentials Mimikatz",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::Bytes(b"mimikatz"),
                Pattern::Bytes(b"sekurlsa"),
                Pattern::StringInsensitive("lsadump"),
            ],
            require_all: false,
        },
        Rule {
            name: "AntiDebug_Techniques",
            description: "Anti-debug actif : IsDebuggerPresent + NtQueryInformationProcess",
            severity: Severity::High,
            // require_all:true — IsDebuggerPresent seul = FP (Tauri, .NET, tout framework)
            patterns: vec![
                Pattern::StringInsensitive("isdebuggerpresent"),
                Pattern::StringInsensitive("checkremotedebuggerpresent"),
            ],
            require_all: true,
        },
        Rule {
            name: "Persistence_Registry",
            description: "Accès clés de démarrage du registre",
            // Medium — outils diagnostic accèdent légitimement à ces clés
            severity: Severity::Medium,
            patterns: vec![
                Pattern::StringInsensitive("software\\microsoft\\windows\\currentversion\\run"),
                Pattern::StringInsensitive("software\\microsoft\\windows nt\\currentversion\\winlogon"),
            ],
            require_all: false,
        },
        Rule {
            name: "Shellcode_Patterns",
            description: "NOP sled extrême (64+ bytes) — shellcode probable",
            severity: Severity::High,
            // 32 NOPs = encore FP dans .rdata/assets Tauri bundlés. 64 NOPs = vraiment anormal.
            // Un NOP sled légitime (alignement compilateur) dépasse rarement 16 bytes.
            patterns: vec![
                Pattern::Bytes(&[
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                ]),
            ],
            require_all: true,
        },
        Rule {
            name: "PowerShell_Encoded_Cmd",
            description: "Commande PowerShell encodée (-EncodedCommand)",
            // Medium — outils diagnostic/admin utilisent légitimement -encodedcommand
            severity: Severity::Medium,
            patterns: vec![
                Pattern::StringInsensitive("powershell"),
                Pattern::StringInsensitive("-encodedcommand"),
            ],
            require_all: true,
        },
        Rule {
            name: "Suspicious_Certutil",
            description: "Utilisation de certutil pour decode/téléchargement",
            severity: Severity::High,
            patterns: vec![
                Pattern::StringInsensitive("certutil"),
                Pattern::StringInsensitive("-decode"),
            ],
            require_all: true,
        },
        // ── Ransomware — familles modernes ────────────────────────────────────
        Rule {
            name: "Ransomware_Modern_Families",
            description: "Noms de familles ransomware connues (LockBit, Conti, BlackCat, REvil…)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("lockbit"),
                Pattern::StringInsensitive("blackcat"),
                Pattern::StringInsensitive("alphv"),
                Pattern::StringInsensitive("revil"),
                Pattern::StringInsensitive("ryuk ransomware"),
                Pattern::StringInsensitive("hive ransomware"),
                Pattern::StringInsensitive("blackbasta"),
            ],
            require_all: false,
        },
        Rule {
            name: "Ransomware_Extensions",
            description: "Extensions de chiffrement ransomware spécifiques",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive(".lockbit"),
                Pattern::StringInsensitive(".conti"),
                Pattern::StringInsensitive(".ryk"),
                Pattern::StringInsensitive(".blackcat"),
            ],
            require_all: false,
        },
        // ── Stealers ──────────────────────────────────────────────────────────
        Rule {
            name: "Stealer_Modern_Families",
            description: "Infostealers connus (RedLine, Raccoon, Vidar, Lumma, AgentTesla, FormBook)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("redline stealer"),
                Pattern::StringInsensitive("raccoon stealer"),
                Pattern::StringInsensitive("vidar"),
                Pattern::StringInsensitive("lumma"),
                Pattern::StringInsensitive("agenttesla"),
                Pattern::StringInsensitive("formbook"),
                Pattern::StringInsensitive("redlinestealer"),
            ],
            require_all: false,
        },
        Rule {
            name: "Discord_Webhook_Exfil",
            description: "Exfiltration via webhook Discord (vol de données)",
            severity: Severity::High,
            patterns: vec![
                Pattern::StringInsensitive("discord.com/api/webhooks/"),
                Pattern::StringInsensitive("discordapp.com/api/webhooks/"),
            ],
            require_all: false,
        },
        // ── Injection / évasion (parité avec version web) ─────────────────────
        Rule {
            name: "Process_Hollowing",
            description: "Process hollowing (NtUnmapViewOfSection + ResumeThread)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("ntunmapviewofsection"),
                Pattern::StringInsensitive("resumethread"),
            ],
            require_all: true,
        },
        Rule {
            name: "AMSI_Bypass",
            description: "Bypass AMSI (antimalware scan interface)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("amsiutils"),
                Pattern::StringInsensitive("amsiinitfailed"),
                Pattern::StringInsensitive("amsiscanbuffer"),
            ],
            require_all: false,
        },
        Rule {
            name: "Defender_Tampering",
            description: "Désactivation de Windows Defender",
            severity: Severity::Critical,
            patterns: vec![Pattern::StringInsensitive("set-mppreference -disablerealtimemonitoring")],
            require_all: false,
        },
        Rule {
            name: "PHP_Webshell",
            description: "Webshell PHP (eval + entrée utilisateur)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("eval($_post"),
                Pattern::StringInsensitive("eval($_get"),
                Pattern::StringInsensitive("eval(base64_decode"),
            ],
            require_all: false,
        },
        Rule {
            name: "Bash_Reverse_Shell",
            description: "Reverse shell bash (/dev/tcp)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("/dev/tcp/"),
                Pattern::StringInsensitive("bash -i"),
            ],
            require_all: true,
        },
        Rule {
            name: "CobaltStrike_Beacon",
            description: "Signatures Cobalt Strike Beacon",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("beacon.dll"),
                Pattern::StringInsensitive("reflectiveloader@4"),
            ],
            require_all: false,
        },
        Rule {
            name: "Common_RAT_Strings",
            description: "Signatures de RATs courants (njRAT, AsyncRAT, QuasarRAT, Remcos)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("njrat"),
                Pattern::StringInsensitive("asyncrat"),
                Pattern::StringInsensitive("quasar.client"),
                Pattern::StringInsensitive("remcos"),
                Pattern::StringInsensitive("nanocore"),
            ],
            require_all: false,
        },
        Rule {
            name: "CryptoMiner_Strings",
            description: "Mineur de cryptomonnaie embarqué",
            severity: Severity::High,
            patterns: vec![
                Pattern::StringInsensitive("stratum+tcp://"),
                Pattern::StringInsensitive("xmrig"),
                Pattern::StringInsensitive("cryptonight"),
                Pattern::StringInsensitive("--donate-level"),
            ],
            require_all: false,
        },
        // ── UAC bypass ────────────────────────────────────────────────────────
        Rule {
            name: "UAC_Bypass_Techniques",
            description: "Bypass UAC connu (fodhelper, eventvwr, sdclt, computerdefaults, silentcleanup)",
            severity: Severity::High,
            patterns: vec![
                Pattern::StringInsensitive("fodhelper.exe"),
                Pattern::StringInsensitive("computerdefaults.exe"),
                Pattern::StringInsensitive("sdclt.exe"),
                Pattern::StringInsensitive("silentcleanup"),
            ],
            require_all: false,
        },
        // ── Macros Office ─────────────────────────────────────────────────────
        Rule {
            name: "Office_Macro_AutoExec",
            description: "Macro Office à exécution automatique (AutoOpen, Workbook_Open)",
            severity: Severity::High,
            patterns: vec![
                Pattern::StringInsensitive("autoopen"),
                Pattern::StringInsensitive("auto_open"),
                Pattern::StringInsensitive("workbook_open"),
                Pattern::StringInsensitive("document_open"),
            ],
            require_all: false,
        },
        // ── Loaders / droppers connus ─────────────────────────────────────────
        Rule {
            name: "Malware_Loader_Families",
            description: "Loaders/droppers connus (Emotet, QakBot, IcedID, Bumblebee, Gozi)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("emotet"),
                Pattern::StringInsensitive("qakbot"),
                Pattern::StringInsensitive("qbot"),
                Pattern::StringInsensitive("icedid"),
                Pattern::StringInsensitive("bumblebee loader"),
                Pattern::StringInsensitive("gozi"),
                Pattern::StringInsensitive("bazarloader"),
            ],
            require_all: false,
        },
        // ── APT / implants ciblés ─────────────────────────────────────────────
        Rule {
            name: "APT_Implant_Families",
            description: "Implants APT connus (PlugX, Winnti, ShadowPad, Sakula, Gh0st RAT)",
            severity: Severity::Critical,
            patterns: vec![
                Pattern::StringInsensitive("plugx"),
                Pattern::StringInsensitive("winnti"),
                Pattern::StringInsensitive("shadowpad"),
                Pattern::StringInsensitive("sakula"),
                Pattern::StringInsensitive("gh0st rat"),
                Pattern::StringInsensitive("poisonivy"),
            ],
            require_all: false,
        },
        // ── Macro Excel 4.0 (XLM) ─────────────────────────────────────────────
        Rule {
            name: "Office_XLM4_Macro",
            description: "Macro Excel 4.0 (XLM) à primitives d'exécution (=EXEC/=CALL/=REGISTER)",
            severity: Severity::High,
            patterns: vec![
                Pattern::StringInsensitive("=exec("),
                Pattern::StringInsensitive("=call("),
                Pattern::StringInsensitive("=register("),
            ],
            require_all: false,
        },
        // ── HTA embarqué ──────────────────────────────────────────────────────
        Rule {
            name: "HTA_Application",
            description: "Application HTA (HTML Application) — vecteur d'exécution de script",
            severity: Severity::High,
            patterns: vec![Pattern::StringInsensitive("<hta:application")],
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
            let matched_strings: Vec<String> = rule
                .patterns
                .iter()
                .filter_map(|p| match_pattern_desc(data, &lower_data, p))
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
