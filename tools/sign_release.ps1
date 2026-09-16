# Copyright 2026 cklinisme
# Licensed under the Apache License, Version 2.0.
# See LICENSE.txt for the full license.
param([string]$Gpg = 'gpg')
$ErrorActionPreference = 'Stop'
$Gpg = (Get-Command $Gpg -ErrorAction Stop).Source
$repoRoot = Split-Path -Parent $PSScriptRoot
$publisherConfig = Get-Content -LiteralPath (Join-Path $repoRoot 'publish-config.json') -Raw | ConvertFrom-Json
if (!$publisherConfig.gpgFingerprint) { throw 'Run setup_signing.ps1 first' }
$publisherRoot = Join-Path $env:LOCALAPPDATA 'doris-connector-publisher\cklinisme'
$keyHome = Join-Path $publisherRoot 'gnupg'
$cygpath = Join-Path (Split-Path $Gpg) 'cygpath.exe'
if (Test-Path -LiteralPath $cygpath) { $keyHome = (& $cygpath -u $keyHome).Trim() }
$secure = (Get-Content -LiteralPath (Join-Path $publisherRoot 'signing-passphrase.dpapi') -Raw).Trim() | ConvertTo-SecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $passphrase = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $passphrase | python (Join-Path $PSScriptRoot 'prepare_release.py') --repository-url $publisherConfig.repositoryUrl --sign --gpg-key $publisherConfig.gpgFingerprint --gpg-executable $Gpg --gnupg-home $keyHome --passphrase-stdin
    if ($LASTEXITCODE -ne 0) { throw 'Release signing failed' }
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $passphrase = $null
}
