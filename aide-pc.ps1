#Requires -Version 5.1
<#
  Aide-diagnostic PC - met en place un acces securise (SSH via un tunnel prive Tailscale)
  pour permettre un diagnostic a distance.

  - Ne contient AUCUN mot de passe.
  - La seule cle autorisee a se connecter est la cle PUBLIQUE de l'ordinateur qui
    fera le diagnostic (une cle publique n'est pas un secret).
  - SSH est ferme au reseau local et a Internet : accessible UNIQUEMENT par le tunnel prive.
  - Peut etre relance sans risque : ce qui est deja fait est reutilise, pas refait.
#>
[CmdletBinding()]
param([string]$TsKey)

$ErrorActionPreference = 'Stop'
# Sans barre de progression, les telechargements de PowerShell 5.1 sont beaucoup plus rapides
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Cle PUBLIQUE autorisee (non secrete) ---
$pub = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqNOu+CExYBd3jIvfi9KoCfL25WrCdZqd+SV+5C2x/Z aide-richard'
$ts  = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'

function Say($msg, $color = 'Cyan') { Write-Host $msg -ForegroundColor $color }
function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
# Adresse 100.x si ce PC est deja relie au tunnel, sinon rien
function Get-TsIp {
  $ErrorActionPreference = 'Continue'
  if (-not (Test-Path $ts)) { return }
  $r = & $ts ip -4 2>$null
  if ($LASTEXITCODE -eq 0 -and "$r" -match '(100\.\d+\.\d+\.\d+)') { $matches[1] }
}
# Reutilise un installateur deja telecharge s'il est intact (signature valide), sinon le telecharge
function Get-Installer($url, $path) {
  if ((Test-Path $path) -and (Get-AuthenticodeSignature $path).Status -eq 'Valid') {
    Say '  (installateur deja telecharge, reutilise)' 'DarkGray'
    return
  }
  Invoke-WebRequest $url -OutFile $path -UseBasicParsing
}
function Install-Msi($path, $extra = '') {
  $p = Start-Process msiexec.exe -ArgumentList "/i `"$path`" /qn /norestart $extra" -Wait -PassThru
  if ($p.ExitCode -notin 0, 3010) { Say "  (code de l'installateur : $($p.ExitCode))" 'Yellow' }
}

if (-not (Test-Admin)) {
  Say "ERREUR : ouvre le Terminal (administrateur), puis relance." 'Red'
  return
}

# La cle est demandee tout de suite (sauf si ce PC est deja relie) : ensuite, plus rien a faire
$ip = Get-TsIp
if (-not $ip) {
  if (-not $TsKey) { $TsKey = Read-Host "Colle la cle recue (tskey-...), puis appuie sur Entree" }
  if ("$TsKey" -match '(tskey-[A-Za-z0-9_-]+)') { $TsKey = $matches[1] }
  else {
    Say "ERREUR : cle invalide (elle commence par tskey-). Relance la ligne et colle la cle." 'Red'
    return
  }
}

Say "[1/5] Serveur SSH..."
if (Get-Service -Name sshd -ErrorAction SilentlyContinue) {
  Say '  (deja installe, reutilise)' 'DarkGray'
} else {
  # Paquet autonome officiel Microsoft/PowerShell : rapide, sans Windows Update
  $a = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'ARM64' } else { 'Win64' }
  $m = Join-Path $env:TEMP 'openssh.msi'
  try {
    Get-Installer "https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview/OpenSSH-$a-v10.0.0.0.msi" $m
    Install-Msi $m
  } catch { Say "  (paquet autonome indisponible : $($_.Exception.Message))" 'Yellow' }
  # Dernier recours : fonctionnalite Windows (passe par Windows Update, peut etre tres long)
  if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
    Say '  Repli par Windows Update (peut etre long)...' 'Yellow'
    try { Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null } catch {}
    $inst = Join-Path $env:WinDir 'System32\OpenSSH\install-sshd.ps1'
    if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue) -and (Test-Path $inst)) {
      try { & $inst | Out-Null } catch {}
    }
  }
  if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
    Say "ERREUR : impossible d'installer le serveur SSH. Envoie une photo de l'ecran." 'Red'
    return
  }
}

Say "[2/5] Cle de diagnostic..."
$akf = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
New-Item -ItemType Directory -Force -Path (Split-Path $akf) | Out-Null
Set-Content -Path $akf -Value $pub -Encoding ascii -Force
# ACL par SID (fonctionne aussi sur un Windows en francais) : Administrateurs + SYSTEME seulement
icacls.exe $akf /inheritance:r /grant "*S-1-5-32-544:F" /grant "*S-1-5-18:F" | Out-Null

Say "[3/5] Service SSH..."
Set-Service -Name sshd -StartupType Automatic
if ((Get-Service -Name sshd).Status -ne 'Running') { Start-Service sshd }

Say "[4/5] Pare-feu : SSH seulement par le tunnel prive..."
# Ferme les regles "SSH ouvert a tous" creees par les installateurs OpenSSH (LAN/Internet),
# puis autorise seulement la plage privee Tailscale (100.64.0.0/10)
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
Get-NetFirewallRule -DisplayName '*OpenSSH*' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
Get-NetFirewallRule -Name 'SSH-Tailscale-Only' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name 'SSH-Tailscale-Only' -DisplayName 'SSH (tunnel prive seulement)' `
  -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any -RemoteAddress '100.64.0.0/10' | Out-Null

Say "[5/5] Tunnel prive (Tailscale)..."
if (Test-Path $ts) {
  Say '  (deja installe, reutilise)' 'DarkGray'
} else {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
  $msi = Join-Path $env:TEMP 'tailscale-setup.msi'
  Get-Installer "https://pkgs.tailscale.com/stable/tailscale-setup-latest-$arch.msi" $msi
  Install-Msi $msi 'TS_UNATTENDEDMODE=always'
}
if (-not $ip) {
  for ($i = 0; $i -lt 20 -and (Get-Service -Name Tailscale -ErrorAction SilentlyContinue).Status -ne 'Running'; $i++) { Start-Sleep -Seconds 1 }
  # Nom distinct par machine (ex. richard-laptop-ab12) pour ne pas confondre les appareils
  $tsName = ('richard-' + $env:COMPUTERNAME.ToLower()) -replace '[^a-z0-9-]', '-'
  & $ts up --auth-key=$TsKey --unattended --hostname=$tsName --accept-routes=false
  for ($i = 0; $i -lt 15 -and -not $ip; $i++) { Start-Sleep -Seconds 2; $ip = Get-TsIp }
}

Write-Host ""
if (-not $ip) {
  Say "ERREUR : le tunnel ne s'est pas connecte. Envoie une photo de l'ecran." 'Red'
  return
}
# Auto-test : SSH joignable par le tunnel ? (un VPN comme NordVPN peut le bloquer)
$ok = $false
try { $c = New-Object Net.Sockets.TcpClient; $ok = $c.ConnectAsync($ip, 22).Wait(4000); $c.Close() } catch {}
Say "=== TERMINE ===" 'Green'
Say ("Nom d'utilisateur Windows : {0}" -f $env:USERNAME) 'Green'
Say ("Nom de l'ordinateur        : {0}" -f $env:COMPUTERNAME) 'Green'
Say ("Adresse privee de ce PC    : {0}" -f $ip) 'Green'
if ($ok) { Say "Test de connexion          : OK" 'Green' }
else { Say "Test de connexion          : BLOQUE - si un VPN (NordVPN...) est actif, deconnecte-le, puis relance la meme ligne." 'Yellow' }
Say "Envoie ces infos a la personne qui fait le diagnostic." 'Green'
