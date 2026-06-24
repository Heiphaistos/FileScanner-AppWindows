// Règles YARA pour scripts (BAT/PS1/VBS) — documentation de référence.

rule PowerShell_Encoded_Command {
    meta:
        description = "Commande PowerShell encodée (EncodedCommand)"
        severity = "High"
    strings:
        $s1 = "powershell" nocase
        $s2 = "-EncodedCommand" nocase
        $s3 = "-enc " nocase
    condition:
        $s1 and ($s2 or $s3)
}

rule PowerShell_Download_Cradle {
    meta:
        description = "Téléchargement de payload PowerShell (DownloadString)"
        severity = "High"
    strings:
        $s1 = "DownloadString" nocase
        $s2 = "Invoke-Expression" nocase
        $s3 = "IEX" nocase
    condition:
        $s1 and ($s2 or $s3)
}

rule Certutil_Abuse {
    meta:
        description = "Abus de certutil pour decode/téléchargement"
        severity = "High"
    strings:
        $s1 = "certutil" nocase
        $s2 = "-decode" nocase
        $s3 = "-urlcache" nocase
    condition:
        $s1 and ($s2 or $s3)
}

rule MSHTA_Bypass {
    meta:
        description = "Exécution HTA via mshta (bypass AppLocker)"
        severity = "Critical"
    strings:
        $s1 = "mshta" nocase
    condition:
        $s1
}

rule Regsvr32_Bypass {
    meta:
        description = "Exécution COM via regsvr32 (bypass AppLocker)"
        severity = "Critical"
    strings:
        $s1 = "regsvr32" nocase
        $s2 = "/s" nocase
        $s3 = "scrobj.dll" nocase
    condition:
        $s1 and ($s2 or $s3)
}

rule Scheduled_Task_Persistence {
    meta:
        description = "Création de tâche planifiée pour persistance"
        severity = "High"
    strings:
        $s1 = "schtasks" nocase
        $s2 = "/create" nocase
    condition:
        all of them
}
