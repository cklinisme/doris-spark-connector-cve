# Copyright 2026 cklinisme
# Licensed under the Apache License, Version 2.0.
# See LICENSE.txt for the full license.
param([string]$Gpg = 'gpg')
$ErrorActionPreference = 'Stop'
$Gpg = (Get-Command $Gpg -ErrorAction Stop).Source
$repoRoot = Split-Path -Parent $PSScriptRoot
$publisherConfig = Get-Content -LiteralPath (Join-Path $repoRoot 'publish-config.json') -Raw | ConvertFrom-Json
$publisherRoot = Join-Path $env:LOCALAPPDATA 'doris-connector-publisher\cklinisme'
$keyHome = Join-Path $publisherRoot 'gnupg'
$secretFile = Join-Path $publisherRoot 'signing-passphrase.dpapi'
New-Item -ItemType Directory -Force -Path $keyHome | Out-Null
$cygpath = Join-Path (Split-Path $Gpg) 'cygpath.exe'
if (Test-Path -LiteralPath $cygpath) { $keyHome = (& $cygpath -u $keyHome).Trim() }
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $publisherRoot /inheritance:r /grant:r "*$($currentSid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict publisher credential directory permissions' }

if (!(Test-Path -LiteralPath $secretFile)) {
    $randomBytes = New-Object byte[] 48
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($randomBytes)
    $rng.Dispose()
    $secure = ConvertTo-SecureString ([Convert]::ToBase64String($randomBytes)) -AsPlainText -Force
    $secure | ConvertFrom-SecureString | Set-Content -LiteralPath $secretFile -Encoding ASCII
    [Array]::Clear($randomBytes, 0, $randomBytes.Length)
}
if (!$publisherConfig.gpgFingerprint) {
    $existing = & $Gpg --homedir $keyHome --batch --with-colons --list-secret-keys 2>$null
    if ($existing -match '^sec:') { throw 'An existing key needs to be recorded in publish-config.json before continuing' }
    $secure = (Get-Content -LiteralPath $secretFile -Raw).Trim() | ConvertTo-SecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $passphrase = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $passphrase | & $Gpg --homedir $keyHome --batch --pinentry-mode loopback --passphrase-fd 0 --quick-generate-key 'cklinisme <330095769+cklinisme@users.noreply.github.com>' rsa3072 sign 2y
        if ($LASTEXITCODE -ne 0) { throw 'GPG key generation failed' }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $passphrase = $null
    }
    $keyDetails = & $Gpg --homedir $keyHome --batch --with-colons --list-secret-keys
    $fingerprints = @($keyDetails | Where-Object { $_.StartsWith('fpr:') } | ForEach-Object { ($_ -split ':')[9] })
    if ($fingerprints.Count -ne 1) { throw 'Expected one signing key' }
    $publisherConfig.gpgFingerprint = $fingerprints[0]
    $publisherConfig | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $repoRoot 'publish-config.json') -Encoding UTF8
}
$publicDir = Join-Path $repoRoot 'public-keys'
New-Item -ItemType Directory -Force -Path $publicDir | Out-Null
& $Gpg --homedir $keyHome --batch --yes --armor --output (Join-Path $publicDir 'cklinisme-release.asc') --export $publisherConfig.gpgFingerprint
if ($LASTEXITCODE -ne 0) { throw 'Public key export failed' }
Write-Output ('Signing fingerprint: ' + $publisherConfig.gpgFingerprint)
Write-Output 'Private key encrypted; passphrase protected by Windows DPAPI for this Windows account.'
