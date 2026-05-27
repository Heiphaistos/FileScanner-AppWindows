# FileScanner v1.0.0 — Script de build production
param([switch]$Dev)

$ErrorActionPreference = "Stop"
$LogDir = ".\.logs"
$LogFile = "$LogDir\build_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force $LogDir | Out-Null }

function Log($msg, $level = "INFO") {
    $line = "[$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')] [$level] $msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Log "=== FileScanner Build ==="

# Kill processus existant
$procs = Get-Process -Name "file-scanner" -ErrorAction SilentlyContinue
if ($procs) {
    Log "Kill processus file-scanner en cours..."
    $procs | ForEach-Object { Stop-Process -Id $_.Id -Force }
    Start-Sleep -Milliseconds 500
}

# Vérifier Node + Cargo
try { node --version | Out-Null } catch { Log "Node.js introuvable" "ERROR"; exit 1 }
try { cargo --version | Out-Null } catch { Log "Rust/Cargo introuvable" "ERROR"; exit 1 }

# npm install si node_modules absent
if (-not (Test-Path "node_modules")) {
    Log "Installation dépendances npm..."
    npm install 2>&1 | ForEach-Object { Log $_ }
    if ($LASTEXITCODE -ne 0) { Log "npm install échoué" "ERROR"; exit 1 }
}

if ($Dev) {
    Log "Lancement en mode développement..."
    npm run tauri dev
} else {
    Log "Build production..."
    npx tauri build 2>&1 | ForEach-Object { Log $_ }

    if ($LASTEXITCODE -ne 0) {
        Log "Build échoué — voir $LogFile" "ERROR"
        exit 1
    }

    $exe = "src-tauri\target\release\file-scanner.exe"
    if (Test-Path $exe) {
        $size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
        Log "Build OK — $exe ($size MB)"
    } else {
        Log "Executable non trouvé après build" "WARN"
    }

    # Nettoyage artefacts temporaires
    $temps = @("src-tauri\target\release\build", "src-tauri\target\release\deps", "src-tauri\target\release\incremental")
    foreach ($t in $temps) {
        if (Test-Path $t) {
            Remove-Item -Recurse -Force $t
            Log "Nettoyé : $t"
        }
    }

    Log "=== Build terminé ==="
}
