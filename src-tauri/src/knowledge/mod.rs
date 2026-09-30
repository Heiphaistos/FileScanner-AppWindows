//! knowledge — Base de connaissances des détections, en français clair.
//!
//! Pour chaque signal (commande de script, règle YARA, API importée, indicateur…) :
//! - `what`    : ce que fait concrètement la commande / l'élément ;
//! - `why_bad` : pourquoi un logiciel malveillant l'utilise ;
//! - `why_ok`  : pourquoi un logiciel légitime l'utilise aussi (piste de faux positif) ;
//! - `base`    : probabilité (%) que CE signal SEUL, sans autre contexte, révèle un
//!               vrai malware. Calibrée sur la fréquence du signal dans les logiciels
//!               légitimes courants : `Start-Process` est partout (bas), un bypass AMSI
//!               n'a quasiment aucun usage honnête (haut).
//!
//! Le moteur `assessment` part de `base` puis l'ajuste avec le contexte réel du fichier
//! (réputation en ligne, signature, co-occurrences, commentaires…).

pub struct Kb {
    pub what: &'static str,
    pub why_bad: &'static str,
    pub why_ok: &'static str,
    pub base: u8,
}

const fn kb(what: &'static str, why_bad: &'static str, why_ok: &'static str, base: u8) -> Kb {
    Kb { what, why_bad, why_ok, base }
}

// ─── Commandes de scripts ─────────────────────────────────────────────────────

pub fn script_call(pattern: &str) -> Kb {
    match pattern.to_ascii_lowercase().as_str() {
        "invoke-expression" | "iex" => kb(
            "Exécute comme du code PowerShell une chaîne de texte construite pendant l'exécution.",
            "C'est la brique de base des « download cradles » : le malware télécharge ou décode un texte puis l'exécute sans jamais l'écrire sur le disque, ce qui échappe aux antivirus.",
            "Certains scripts d'installation (Chocolatey, Scoop, modules) l'utilisent pour exécuter un installeur officiel. C'est une mauvaise pratique mais pas un virus si la source est connue.",
            40,
        ),
        "downloadstring" => kb(
            "Télécharge le contenu d'une URL directement en mémoire, sous forme de texte.",
            "Presque toujours combiné à IEX pour exécuter un script distant sans trace sur le disque.",
            "Utilisé par des scripts d'administration pour lire une API ou une page de version.",
            35,
        ),
        "downloadfile" => kb(
            "Télécharge un fichier depuis Internet et l'enregistre sur le disque.",
            "Permet à un « dropper » de récupérer la charge malveillante réelle après l'infection initiale.",
            "Très courant dans les scripts d'installation ou de mise à jour qui récupèrent un binaire officiel.",
            22,
        ),
        "webclient" => kb(
            "Crée un client HTTP .NET pour communiquer avec un serveur web.",
            "Sert à contacter le serveur de l'attaquant (téléchargement, exfiltration).",
            "Usage réseau banal : appels d'API, vérification de mises à jour.",
            12,
        ),
        "invoke-webrequest" => kb(
            "Envoie une requête HTTP (équivalent PowerShell de curl).",
            "Peut télécharger une charge malveillante ou envoyer des données volées.",
            "Commande standard pour interroger une API ou télécharger un outil officiel.",
            10,
        ),
        "start-process" => kb(
            "Lance un autre programme.",
            "Un malware l'utilise pour exécuter la charge qu'il vient de déposer.",
            "Présent dans énormément de scripts légitimes (lancer un installeur, ouvrir un outil).",
            8,
        ),
        "cmd.exe" => kb(
            "Appelle l'interpréteur de commandes Windows.",
            "Permet d'enchaîner des commandes système (suppression, copie, lancement de charge).",
            "Très courant dans les scripts d'administration et les installeurs.",
            8,
        ),
        "powershell.exe" => kb(
            "Lance PowerShell depuis un autre script ou programme.",
            "Technique classique pour exécuter une commande cachée ou encodée depuis un document ou un raccourci.",
            "Les outils d'administration et installeurs appellent PowerShell normalement.",
            12,
        ),
        "reg.exe" => kb(
            "Lit ou modifie le registre Windows en ligne de commande.",
            "Sert à installer une persistance (démarrage automatique) ou à désactiver des protections.",
            "Les installeurs et scripts de configuration écrivent légitimement dans le registre.",
            18,
        ),
        "schtasks" => kb(
            "Crée ou modifie une tâche planifiée Windows.",
            "Moyen courant pour qu'un malware se relance automatiquement (persistance).",
            "Les logiciels de mise à jour (navigateurs, antivirus, sauvegardes) créent des tâches planifiées.",
            22,
        ),
        "net user" => kb(
            "Liste, crée ou modifie des comptes utilisateurs Windows.",
            "Un attaquant crée un compte caché ou change un mot de passe pour garder l'accès.",
            "Scripts d'administration système et de provisionnement de postes.",
            25,
        ),
        "net localgroup" => kb(
            "Ajoute ou retire des comptes de groupes locaux (dont Administrateurs).",
            "Élévation de privilèges : ajout d'un compte pirate au groupe Administrateurs.",
            "Scripts d'administration pour configurer des postes.",
            28,
        ),
        "netsh" => kb(
            "Configure le réseau et le pare-feu Windows.",
            "Ouvre des ports ou désactive le pare-feu pour permettre un accès à distance.",
            "Outils VPN, jeux et serveurs locaux ajoutent des règles de pare-feu.",
            18,
        ),
        "wmic" => kb(
            "Interroge ou pilote Windows via WMI (processus, matériel, services).",
            "Exécution de commandes à distance, reconnaissance, suppression des copies de sauvegarde.",
            "Scripts d'inventaire matériel et d'administration (outil ancien mais répandu).",
            15,
        ),
        "certutil" => kb(
            "Outil Windows de gestion de certificats, capable aussi de télécharger et décoder des fichiers.",
            "Détourné (« LOLBin ») pour télécharger ou décoder une charge sans outil suspect.",
            "Gestion légitime de certificats, calcul d'empreintes (certutil -hashfile).",
            38,
        ),
        "bitsadmin" => kb(
            "Pilote le service de transfert en arrière-plan BITS de Windows.",
            "Téléchargement discret de charges malveillantes, parfois persistant.",
            "Ancien outil de déploiement ; encore utilisé dans quelques scripts d'entreprise.",
            42,
        ),
        "mshta" => kb(
            "Exécute une « application HTML » (HTA) contenant du VBScript/JScript.",
            "Très utilisé pour exécuter du code distant en contournant les protections : rare dans un usage honnête.",
            "Quelques vieux outils internes d'entreprise sont des applications HTA.",
            62,
        ),
        "regsvr32" => kb(
            "Enregistre une DLL COM dans Windows.",
            "Technique « Squiblydoo » : exécute un script distant via /i:http… en contournant AppLocker.",
            "Les installeurs enregistrent légitimement des composants COM.",
            35,
        ),
        "rundll32" => kb(
            "Exécute une fonction exportée par une DLL.",
            "Lance une DLL malveillante via un binaire Windows de confiance.",
            "Windows et beaucoup de programmes l'utilisent (panneau de configuration, impression…).",
            15,
        ),
        "vssadmin delete" | "wbadmin delete" => kb(
            "Supprime les clichés instantanés (Volume Shadow Copy) ou les sauvegardes système de Windows.",
            "Geste signature d'un rançongiciel juste avant le chiffrement : effacer les sauvegardes empêche la victime de restaurer ses fichiers sans payer.",
            "Presque aucun usage légitime d'une suppression totale et silencieuse (« /all /quiet ») ; tout au plus un outil de maintenance très spécifique, jamais un logiciel grand public.",
            85,
        ),
        "bcdedit" => kb(
            "Modifie la configuration de démarrage de Windows (Boot Configuration Data).",
            "Un rançongiciel l'utilise pour désactiver la réparation automatique et la restauration système après chiffrement.",
            "Usage légitime réservé à l'administration système avancée et à certains installeurs de double amorçage.",
            60,
        ),
        _ => kb(
            "Commande ou appel sensible détecté dans le script.",
            "Peut être utilisé pour exécuter ou dissimuler une action malveillante.",
            "Peut aussi apparaître dans un script d'administration légitime.",
            15,
        ),
    }
}

mod yara;
pub use yara::yara_rule;

// ─── Fonctions importées par un exécutable ────────────────────────────────────

pub fn import(name: &str) -> Kb {
    let n = name.to_ascii_lowercase();
    let has = |k: &str| n.contains(&k.to_ascii_lowercase());
    if has("CreateRemoteThread") || has("RtlCreateUserThread") {
        kb(
            "Démarre l'exécution de code à l'intérieur d'un AUTRE programme.",
            "Pièce maîtresse de l'injection de code : le malware se cache dans un processus de confiance.",
            "Débogueurs, profileurs, outils d'accessibilité et anti-triche l'utilisent.",
            28,
        )
    } else if has("WriteProcessMemory") {
        kb(
            "Écrit dans la mémoire d'un autre programme.",
            "Dépose le code malveillant dans un processus victime.",
            "Débogueurs, « trainers » de jeux, outils de patch.",
            20,
        )
    } else if has("NtUnmapViewOfSection") || has("ZwUnmapViewOfSection") {
        kb(
            "Retire une partie de la mémoire d'un processus.",
            "Première étape du « process hollowing » (vider un programme sain pour y loger un malware).",
            "Rarement importé directement par un logiciel ordinaire.",
            35,
        )
    } else if has("QueueUserAPC") {
        kb(
            "Programme l'exécution d'une fonction dans un autre thread.",
            "Technique d'injection discrète (« APC injection »).",
            "Utilisée par des frameworks d'E/S asynchrones et certains runtimes.",
            18,
        )
    } else if has("VirtualAllocEx") {
        kb(
            "Réserve de la mémoire dans un AUTRE programme.",
            "Prépare l'espace où sera injecté du code malveillant.",
            "Débogueurs et outils système.",
            15,
        )
    } else if has("VirtualAlloc") {
        kb(
            "Réserve de la mémoire pour le programme lui-même.",
            "Les packers et shellcodes y décompressent leur code caché.",
            "Présent dans quasiment tous les programmes (gestion mémoire, moteurs JavaScript, jeux).",
            3,
        )
    } else if has("SetWindowsHookEx") {
        kb(
            "Installe un « hook » qui intercepte des événements Windows (clavier, souris).",
            "Enregistreurs de frappe.",
            "Raccourcis clavier globaux, outils d'accessibilité, logiciels de capture.",
            12,
        )
    } else if has("GetAsyncKeyState") {
        kb(
            "Lit l'état d'une touche du clavier.",
            "Enregistreurs de frappe rudimentaires.",
            "Jeux vidéo et raccourcis clavier : extrêmement courant.",
            5,
        )
    } else if has("URLDownloadToFile") {
        kb(
            "Télécharge un fichier depuis Internet vers le disque.",
            "Les « droppers » récupèrent la charge malveillante.",
            "Mises à jour automatiques et installeurs web.",
            14,
        )
    } else if has("WinExec") || has("ShellExecute") || has("CreateProcess") {
        kb(
            "Lance un autre programme.",
            "Exécute une charge déposée ou une commande système.",
            "Fonction de base utilisée par la quasi-totalité des applications (ouvrir un lien, lancer un outil).",
            3,
        )
    } else if has("OpenProcess") || has("ReadProcessMemory") {
        kb(
            "Accède à un autre programme en cours d'exécution.",
            "Lecture de la mémoire d'un navigateur ou de LSASS pour voler des identifiants.",
            "Gestionnaires de tâches, antivirus, outils de surveillance.",
            5,
        )
    } else if has("IsDebuggerPresent") || has("CheckRemoteDebuggerPresent") || has("NtQueryInformationProcess") {
        kb(
            "Détecte si le programme est débogué.",
            "Anti-analyse : le malware se cache des chercheurs.",
            "Protections anti-piratage et runtimes (très courant, y compris dans le code de démarrage standard de Visual C++).",
            3,
        )
    } else if has("CryptEncrypt") || has("CryptDecrypt") || has("CryptAcquireContext") {
        kb(
            "Utilise la cryptographie Windows.",
            "Les rançongiciels chiffrent vos fichiers ; d'autres malwares chiffrent leurs communications.",
            "Chiffrement légitime : HTTPS, stockage sécurisé, licences, signatures.",
            4,
        )
    } else if has("InternetOpen") || has("InternetConnect") {
        kb(
            "Ouvre une connexion Internet (WinINet).",
            "Communication avec le serveur de l'attaquant.",
            "Toute application qui vérifie ses mises à jour ou appelle une API.",
            3,
        )
    } else if has("AdjustTokenPrivileges") {
        kb(
            "Active des privilèges spéciaux du compte (ex. débogage, arrêt du système).",
            "Obtenir le droit de manipuler d'autres processus.",
            "Installeurs, outils d'administration, programmes qui redémarrent l'ordinateur.",
            6,
        )
    } else if has("GetClipboardData") {
        kb(
            "Lit le presse-papiers.",
            "Les « clippers » remplacent une adresse de portefeuille copiée par celle de l'attaquant.",
            "Tout éditeur de texte ou application avec copier-coller.",
            3,
        )
    } else if has("BitBlt") {
        kb(
            "Copie une zone de l'écran.",
            "Capture d'écran à l'insu de l'utilisateur.",
            "Fonction graphique de base utilisée par presque toutes les interfaces.",
            2,
        )
    } else if has("RegSetValue") {
        kb(
            "Écrit dans le registre Windows.",
            "Persistance ou désactivation de protections.",
            "Sauvegarde de préférences : omniprésent.",
            3,
        )
    } else if has("ptrace") {
        kb(
            "Permet d'observer ou de contrôler un autre processus (Linux).",
            "Injection de code, anti-débogage ou vol de secrets en mémoire.",
            "Débogueurs (gdb), outils de trace (strace), sandboxes.",
            20,
        )
    } else if has("memfd_create") {
        kb(
            "Crée un fichier qui n'existe qu'en mémoire (Linux).",
            "Exécution « sans fichier » d'une charge malveillante.",
            "Navigateurs, runtimes et outils de conteneurs l'utilisent pour de la mémoire partagée.",
            18,
        )
    } else if has("mprotect") || has("dlopen") {
        kb(
            "Change les droits d'une zone mémoire / charge une bibliothèque à la volée.",
            "Décompression et exécution de code caché.",
            "Utilisé par presque tous les programmes Linux dynamiques (JIT, plugins).",
            3,
        )
    } else if has("setuid") || has("setgid") || has("chroot") {
        kb(
            "Change l'identité ou la racine du processus.",
            "Élévation ou maintien de privilèges.",
            "Démons système qui abandonnent leurs privilèges par sécurité.",
            5,
        )
    } else {
        kb(
            "Fonction système sensible importée par le programme.",
            "Peut servir à un comportement malveillant.",
            "Fonction système utilisée aussi par de nombreux logiciels légitimes.",
            3,
        )
    }
}

// ─── Autres indicateurs ───────────────────────────────────────────────────────

pub fn other(ioc_type: &str, value: &str) -> Kb {
    match ioc_type {
        "Entropie" => kb(
            "Une partie du programme ressemble à des données compressées ou chiffrées (entropie élevée).",
            "Les malwares chiffrent leur code pour le cacher aux antivirus.",
            "Les installeurs, jeux et programmes contenant des images, polices ou archives ont naturellement une forte entropie.",
            8,
        ),
        "Packing" => kb(
            "Section à très forte entropie sans packer identifié.",
            "Possible chiffrement « maison » du code malveillant.",
            "Ressources compressées (images, données de jeu, archives embarquées).",
            12,
        ),
        "Packer" => kb(
            "Signature d'un compresseur/protecteur d'exécutable.",
            "Cache le code réel à l'analyse.",
            "Beaucoup de logiciels légitimes sont compressés (UPX) ou protégés contre le piratage.",
            15,
        ),
        "Signature" => kb(
            "Le programme n'a pas de signature numérique d'éditeur.",
            "Un malware est rarement signé (certificat coûteux et traçable).",
            "La majorité des logiciels open source, outils portables et petits projets ne sont pas signés.",
            4,
        ),
        "ELF" => kb(
            "Le binaire Linux n'a aucun symbole (strippé).",
            "Complique l'analyse du malware.",
            "Les binaires de production sont très souvent strippés pour réduire leur taille.",
            4,
        ),
        "Archive" if value.contains("chiffr") || value.contains("Entrées") => kb(
            "L'archive est protégée par mot de passe.",
            "Empêche l'antivirus d'inspecter le contenu : technique d'évasion classique par e-mail.",
            "Beaucoup d'utilisateurs protègent leurs archives personnelles ou professionnelles.",
            20,
        ),
        "Archive" if value.contains("Exécutable") => kb(
            "L'archive contient un ou plusieurs programmes exécutables.",
            "Moyen courant de distribuer un malware.",
            "Normal pour une archive de logiciel (installeur, outil portable).",
            8,
        ),
        "Archive" => kb(
            "Un fichier de l'archive a une double extension trompeuse (ex. facture.pdf.exe).",
            "Ruse pour faire passer un programme pour un document.",
            "Quasiment jamais légitime.",
            80,
        ),
        "Macro VBA" => kb(
            "Le document Office contient des macros VBA.",
            "Les macros sont le vecteur d'infection historique par pièce jointe.",
            "Nombreux tableurs et modèles d'entreprise utilisent des macros.",
            25,
        ),
        "PDF" if value.contains("Launch") => kb(
            "Le PDF peut lancer un programme externe.",
            "Exécution de code au clic dans le document.",
            "Quasiment jamais utilisé dans un PDF légitime.",
            60,
        ),
        "PDF" if value.contains("JavaScript") => kb(
            "Le PDF contient du JavaScript.",
            "Exploitation de failles du lecteur PDF.",
            "Formulaires interactifs (calculs automatiques, validation de champs).",
            18,
        ),
        "PDF" => kb(
            "Le PDF contient une action automatique, un formulaire XFA ou des fichiers joints.",
            "Peut déclencher du code ou livrer un fichier piégé.",
            "Formulaires administratifs, factures avec pièces jointes, documents interactifs.",
            10,
        ),
        "Réseau Tor" => kb(
            "Contient une adresse du réseau anonyme Tor (.onion).",
            "Communication cachée avec l'attaquant (rançongiciels, C2).",
            "Navigateurs, clients Tor, articles et outils de confidentialité.",
            35,
        ),
        "Crypto wallet" => kb(
            "Contient une adresse de portefeuille Bitcoin.",
            "Adresse de paiement de rançon ou de mineur.",
            "Dons, portefeuilles, sites marchands, documentation.",
            12,
        ),
        "Réseau" => kb(
            "Contient beaucoup d'adresses web.",
            "Liste de serveurs de commande ou de téléchargement.",
            "Navigateurs, documentation, bibliothèques réseau.",
            3,
        ),
        "Persistance" => kb(
            "Référence une clé de démarrage automatique du registre.",
            "Le malware se relance à chaque démarrage.",
            "Nombreux logiciels légitimes se lancent au démarrage.",
            10,
        ),
        "Obfuscation" => kb(
            "Le script contient du texte encodé ou brouillé (Base64, hexadécimal, concaténations).",
            "Cache le vrai code aux antivirus et aux humains.",
            "Scripts minifiés, données embarquées (images, certificats), générateurs de code.",
            20,
        ),
        _ => kb(
            "Indicateur technique détecté dans le fichier.",
            "Peut être lié à un comportement malveillant.",
            "Peut aussi être présent dans un fichier légitime.",
            10,
        ),
    }
}
