//! Connaissance des règles de détection (YARA).

use super::{kb, Kb};
use crate::txt;

// ─── Règles YARA ──────────────────────────────────────────────────────────────

/// Connaissance d'une règle ; `matched` = motifs réellement trouvés : certains
/// motifs sont très spécifiques (preuve forte), d'autres banals (preuve faible).
pub fn yara_rule(rule: &str, matched: &[String]) -> Kb {
    let m = |needle: &str| matched.iter().any(|s| s.to_ascii_lowercase().contains(needle));
    let n = matched.len();
    match rule {
        "EICAR_Test_File" => kb(
            "Fichier de test standard EICAR : une simple chaîne de texte que TOUS les antivirus doivent signaler.",
            "Par convention internationale, il est traité exactement comme un virus pour vérifier que la protection fonctionne.",
            "Il ne contient aucun code dangereux : s'il vient d'un test volontaire, c'est normal qu'il soit détecté.",
            99,
        ),
        "UPX_Packer" => kb(
            "Le programme est compressé avec UPX, un compresseur d'exécutables open source.",
            "Compresser un malware change son empreinte et gêne l'analyse.",
            "UPX est très utilisé par des logiciels légitimes pour réduire leur taille (outils en Go, jeux indépendants, utilitaires portables).",
            15,
        ),
        "MPRESS_Packer" => kb(
            "Le programme est compressé par un « packer » commercial.",
            "Le packer masque le vrai code du programme à l'antivirus.",
            "Certains éditeurs l'utilisent pour réduire la taille ou limiter la copie.",
            28,
        ),
        "Additional_Packers" => kb(
            txt!("Le programme est protégé par un logiciel anti-analyse (VMProtect, Themida, Enigma…)."),
            "Rend l'analyse très difficile : apprécié des malwares pour échapper aux chercheurs.",
            "Utilisé par des jeux, anti-triche et logiciels commerciaux contre le piratage.",
            30,
        ),
        "Ransomware_Strings" => kb(
            "Contient des phrases ou noms de fichiers typiques d'une note de rançon.",
            "Un rançongiciel affiche ce message après avoir chiffré vos fichiers.",
            "Un article, un cours de sécurité ou un outil de déchiffrement peut citer ces phrases.",
            if n >= 2 { 72 } else { 55 },
        ),
        "Ransomware_Payment" => kb(
            "Mentionne à la fois Bitcoin et le navigateur Tor.",
            "Instructions de paiement de rançon typiques.",
            "Portefeuilles, guides de confidentialité ou articles de presse citent aussi Bitcoin et Tor.",
            30,
        ),
        "Ransomware_Modern_Families" | "Ransomware_Extensions" => kb(
            "Contient le nom ou l'extension d'une famille de rançongiciel connue.",
            "Le malware se nomme lui-même ou renomme vos fichiers avec cette extension.",
            "Un outil de sécurité, un rapport ou un déchiffreur cite aussi ces noms.",
            45,
        ),
        "Process_Injection" => kb(
            txt!("Le programme peut écrire du code dans un AUTRE programme puis l'y exécuter (VirtualAllocEx + CreateRemoteThread)."),
            "Permet au malware de se cacher dans un processus de confiance (explorer.exe, navigateur).",
            "Débogueurs, anti-triche, outils d'accessibilité et certains lanceurs utilisent ces mêmes fonctions.",
            42,
        ),
        "Process_Hollowing" => kb(
            "Le programme peut vider un processus légitime et le remplacer par un autre code.",
            "Technique de camouflage avancée : le malware tourne sous l'identité d'un programme sain.",
            "Très rare dans un logiciel légitime (quelques protections logicielles).",
            58,
        ),
        "Shellcode_Patterns" => kb(
            "Contient une longue suite d'instructions « NOP » (octets 0x90).",
            "Typique des exploits qui préparent l'exécution d'un shellcode.",
            "Peut apparaître dans des données compressées, des images ou du remplissage de compilateur.",
            22,
        ),
        "Keylogger_Strings" => kb(
            "Utilise les fonctions qui lisent l'état du clavier.",
            "Un enregistreur de frappe capture ce que vous tapez (mots de passe).",
            "Jeux, raccourcis clavier globaux, logiciels d'accessibilité lisent aussi le clavier.",
            18,
        ),
        "Mimikatz_Strings" | "LSASS_Credential_Dumping" => kb(
            txt!("Contient des marqueurs d'outils d'extraction de mots de passe Windows (Mimikatz, dump LSASS)."),
            "Vol des identifiants de tous les utilisateurs connectés.",
            "Outils d'audit de sécurité et documentation de pentest (usage professionnel encadré).",
            if n >= 2 { 88 } else { 72 },
        ),
        "CobaltStrike_Beacon" | "C2_PostEx_Frameworks" => kb(
            "Contient des marqueurs de frameworks d'attaque (Cobalt Strike, Metasploit, Sliver…).",
            "Implant qui donne à l'attaquant le contrôle total de la machine.",
            "Tests d'intrusion autorisés, documentation ou règles de détection qui citent ces noms.",
            if n >= 2 { 85 } else { 65 },
        ),
        "Common_RAT_Strings" | "RAT_Families_2" | "APT_Implant_Families" => kb(
            "Contient le nom d'un outil de prise de contrôle à distance malveillant connu (RAT).",
            "Un RAT permet à l'attaquant de voir l'écran, voler des fichiers, activer la webcam…",
            "Un rapport de sécurité, une liste de détection ou un antivirus cite aussi ces noms.",
            if n >= 2 { 75 } else { 50 },
        ),
        "CryptoMiner_Strings" | "GPU_Miner_Binaries" => kb(
            "Contient des marqueurs de logiciel de minage de cryptomonnaie.",
            "Un mineur caché utilise votre processeur/carte graphique à votre insu.",
            txt!("Si VOUS avez téléchargé un mineur (XMRig, lolMiner…) volontairement, c'est normal."),
            if m("stratum+tcp") { 55 } else { 40 },
        ),
        "PHP_Webshell" => kb(
            "Exécute directement du code envoyé dans une requête web.",
            "Porte dérobée sur un serveur : l'attaquant exécute ce qu'il veut à distance.",
            "Pratiquement jamais légitime ; parfois dans des exemples de cours de sécurité.",
            85,
        ),
        "Bash_Reverse_Shell" => kb(
            "Ouvre un terminal accessible à distance via le réseau.",
            "Donne un contrôle complet de la machine à l'attaquant.",
            "Exercices de sécurité (CTF) ou documentation.",
            82,
        ),
        "Network_Downloader" => kb(
            txt!("Utilise URLDownloadToFile pour télécharger un fichier."),
            "Les « droppers » téléchargent la vraie charge malveillante avec cette fonction.",
            "Mises à jour automatiques, installeurs web, lanceurs de jeux.",
            18,
        ),
        "AntiDebug_Techniques" => kb(
            "Vérifie si le programme est surveillé par un débogueur.",
            "Le malware change de comportement quand un chercheur l'analyse.",
            "Très courant dans les logiciels commerciaux, jeux et protections anti-piratage.",
            12,
        ),
        "AMSI_Bypass" => kb(
            "Tente de désactiver AMSI, l'interface qui permet à l'antivirus d'inspecter les scripts.",
            "Rend l'antivirus aveugle : technique d'attaque sans usage grand public légitime.",
            "Outils de pentest et règles de détection qui citent ces noms.",
            85,
        ),
        "Defender_Tampering" => kb(
            "Désactive la protection en temps réel de Windows Defender.",
            "Laisse le champ libre au malware.",
            "Scripts d'optimisation « gaming » ou de débridage (déconseillés mais pas malveillants).",
            65,
        ),
        "PowerShell_Encoded_Cmd" => kb(
            txt!("Lance PowerShell avec une commande encodée en Base64 (-EncodedCommand)."),
            "Masque la commande réellement exécutée.",
            "Des outils de gestion (SCCM, Intune) encodent aussi leurs commandes pour éviter les problèmes de guillemets.",
            45,
        ),
        "Suspicious_Certutil" => kb(
            "Utilise certutil pour décoder un fichier.",
            "Décode une charge cachée avec un outil Windows de confiance.",
            "Conversion légitime de certificats.",
            45,
        ),
        "Persistence_Registry" => kb(
            "Fait référence aux clés de registre de démarrage automatique (Run, Winlogon).",
            "Le malware s'inscrit pour se relancer à chaque démarrage.",
            "Énormément de logiciels légitimes se lancent au démarrage (messageries, synchronisation, pilotes).",
            12,
        ),
        "Stealer_Modern_Families" | "Stealer_Families_3" => kb(
            txt!("Contient le nom d'un voleur d'informations connu (RedLine, Lumma, Vidar…)."),
            "Ces malwares volent mots de passe, cookies et portefeuilles.",
            txt!("Les noms courts (« vidar », « lumma ») peuvent apparaître par hasard dans un texte ou un nom propre."),
            if n >= 2 { 70 } else { 40 },
        ),
        "Discord_Webhook_Exfil" => kb(
            "Contient une URL de webhook Discord.",
            "Les voleurs envoient les données dérobées vers un salon Discord de l'attaquant.",
            "Bots, outils de notification et intégrations CI envoient des messages sur Discord de la même façon.",
            30,
        ),
        "UAC_Bypass_Techniques" => kb(
            "Fait référence à des programmes Windows détournables pour obtenir les droits administrateur sans confirmation.",
            "Élévation de privilèges silencieuse.",
            txt!("Ces noms (eventvwr.exe, sdclt.exe…) sont aussi cités par des outils système et de diagnostic."),
            35,
        ),
        "Office_Macro_AutoExec" => kb(
            "Contient une macro qui s'exécute automatiquement à l'ouverture du document.",
            "Vecteur d'infection n°1 par pièce jointe : ouvrir le document suffit.",
            "Modèles d'entreprise et tableurs métiers automatisent des tâches à l'ouverture.",
            40,
        ),
        "Office_XLM4_Macro" => kb(
            "Contient une macro Excel 4.0 capable d'exécuter des commandes.",
            "Technique d'infection qui échappait longtemps aux antivirus.",
            "Très rare de nos jours dans un fichier légitime.",
            60,
        ),
        "HTA_Application" => kb(
            "Le fichier est une application HTML (HTA) exécutable par Windows.",
            "Vecteur fréquent de première infection.",
            "Quelques anciens outils internes.",
            45,
        ),
        "Malware_Loader_Families" | "Loader_Families_2" => kb(
            txt!("Contient le nom d'un « loader » malveillant connu (Emotet, QakBot, GuLoader…)."),
            "Un loader installe d'autres malwares (rançongiciels, voleurs).",
            txt!("Des noms courts (« gozi », « qbot ») peuvent apparaître dans un rapport ou une liste de détection."),
            if n >= 2 { 72 } else { 45 },
        ),
        "Impacket_Lateral_Movement" | "AD_Attack_Tools" => kb(
            txt!("Fait référence à des outils d'attaque de réseau d'entreprise (Impacket, Rubeus, SharpHound…)."),
            "Propagation dans le réseau et vol d'identifiants Active Directory.",
            "Outils de pentest et d'audit utilisés par les équipes sécurité.",
            if n >= 2 { 65 } else { 45 },
        ),
        "Wiper_Families" => kb(
            "Contient le nom d'un malware destructeur connu (wiper).",
            "Efface définitivement les données et rend la machine inutilisable.",
            "Rapports de sécurité ou règles de détection citant ces noms.",
            60,
        ),
        _ => kb(
            "Motif caractéristique d'un comportement malveillant détecté.",
            "Ce motif est associé à des logiciels malveillants connus.",
            "Il peut aussi apparaître dans un fichier légitime qui mentionne ce comportement.",
            30,
        ),
    }
}
