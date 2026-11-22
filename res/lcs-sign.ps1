<#
  LCRustdesk build signing. Signs every not-yet-signed .exe/.dll/.msi under the given
  paths with the code-signing certificate from the LCS_SIGN_PFX (base64) and
  LCS_SIGN_PFX_PASSWORD environment variables, SHA-256 with an RFC 3161 timestamp.
  Fails the build if the certificate is missing or any file ends up unsigned.
  Files already signed by someone else (e.g. Microsoft runtime DLLs) are left alone.
#>
param([Parameter(Mandatory)][string[]]$Path)
$ErrorActionPreference = 'Stop'

if (-not $env:LCS_SIGN_PFX -or -not $env:LCS_SIGN_PFX_PASSWORD) {
    throw 'LCS_SIGN_PFX / LCS_SIGN_PFX_PASSWORD secrets are not set; refusing to produce an unsigned build.'
}

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'signtool.exe not found' }

$files = @(Get-ChildItem -Path $Path -Recurse -File -Include *.exe, *.dll, *.msi |
    Where-Object { -not (Get-AuthenticodeSignature $_.FullName).SignerCertificate })
if (-not $files) { throw "Nothing to sign under: $($Path -join ', ')" }

$pfx = Join-Path $env:RUNNER_TEMP 'lcs-sign.pfx'
try {
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:LCS_SIGN_PFX))
    # Batches keep the command line short; signtool signs every file it is given.
    for ($i = 0; $i -lt $files.Count; $i += 20) {
        $batch = $files[$i..([Math]::Min($i + 19, $files.Count - 1))].FullName
        & $signtool.FullName sign /f $pfx /p $env:LCS_SIGN_PFX_PASSWORD /fd SHA256 `
            /tr http://timestamp.digicert.com /td SHA256 /q $batch
        if ($LASTEXITCODE -ne 0) { throw "signtool failed (exit $LASTEXITCODE)" }
    }
} finally {
    Remove-Item $pfx -Force -ErrorAction SilentlyContinue
}

# The internal CA isn't trusted on GitHub's runner, so check for a signature + timestamp
# rather than full chain validation (that is checked on a domain PC).
$bad = foreach ($f in $files) {
    $s = Get-AuthenticodeSignature $f.FullName
    if (-not $s.SignerCertificate -or -not $s.TimeStamperCertificate) { $f.FullName }
}
if ($bad) { throw "Unsigned or untimestamped after signing: $($bad -join ', ')" }
$s = Get-AuthenticodeSignature $files[0].FullName
"Signed $($files.Count) file(s) as: $($s.SignerCertificate.Subject)"
"Certificate thumbprint: $($s.SignerCertificate.Thumbprint)"
