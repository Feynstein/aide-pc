#Requires -Version 5.1
<#
  Aide-diagnostic PC - met en place un acces securise (SSH via un tunnel prive Tailscale)
  pour permettre un diagnostic a distance.

  - Ne contient AUCUN mot de passe.
  - La seule cle autorisee a se connecter est la cle PUBLIQUE de l'ordinateur qui
    fera le diagnostic (une cle publique n'est pas un secret).
  - SSH est ferme au reseau local et a Internet : accessible UNIQUEMENT par le tunnel prive.
#>
[CmdletBinding()]
param([string]$TsKey)

$ErrorActionPreference = 'Stop'

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) {
  Write-Host "ERREUR : ouvre Windows PowerShell en tant qu'ADMINISTRATEUR, puis relance." -ForegroundColor Red
  return
}

# --- Cle PUBLIQUE autorisee (non secrete) ---
$pub = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqNOu+CExYBd3jIvfi9KoCfL25WrCdZqd+SV+5C2x/Z aide-richard'

Write-Host "[1/5] Installation du serveur OpenSSH..." -ForegroundColor Cyan
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null }

Write-Host "[2/5] Autorisation de la cle de diagnostic..." -ForegroundColor Cyan
$akf = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
New-Item -ItemType Directory -Force -Path (Split-Path $akf) | Out-Null
Set-Content -Path $akf -Value $pub -Encoding ascii -Force
# ACL par SID (fonctionne aussi sur un Windows en francais) : Administrateurs + SYSTEME seulement
icacls.exe $akf /inheritance:r /grant "*S-1-5-32-544:F" /grant "*S-1-5-18:F" | Out-Null

Write-Host "[3/5] Demarrage du service SSH..." -ForegroundColor Cyan
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

Write-Host "[4/5] Pare-feu : SSH accessible uniquement via le tunnel prive..." -ForegroundColor Cyan
# Ferme SSH au LAN/Internet, autorise seulement la plage privee Tailscale (100.64.0.0/10)
Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
if (Get-NetFirewallRule -Name 'SSH-Tailscale-Only' -ErrorAction SilentlyContinue) {
  Remove-NetFirewallRule -Name 'SSH-Tailscale-Only'
}
New-NetFirewallRule -Name 'SSH-Tailscale-Only' -DisplayName 'SSH (tunnel prive seulement)' `
  -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -RemoteAddress '100.64.0.0/10' | Out-Null

Write-Host "[5/5] Installation du tunnel prive (Tailscale)..." -ForegroundColor Cyan
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$msi = Join-Path $env:TEMP 'tailscale-setup.msi'
Invoke-WebRequest "https://pkgs.tailscale.com/stable/tailscale-setup-latest-$arch.msi" -OutFile $msi -UseBasicParsing
Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart TS_UNATTENDEDMODE=always" -Wait

$ts = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
if (-not $TsKey) { $TsKey = Read-Host "Colle la cle recue par texto, puis appuie sur Entree" }

& $ts up --auth-key=$TsKey --unattended --hostname=richard-pc --accept-routes=false

Start-Sleep -Seconds 3
$ip = (& $ts ip -4)
Write-Host ""
Write-Host "=== TERMINE ===" -ForegroundColor Green
Write-Host "Adresse privee de ce PC : $ip" -ForegroundColor Green
Write-Host "Donne cette adresse a la personne qui fait le diagnostic." -ForegroundColor Green
