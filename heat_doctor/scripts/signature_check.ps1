# Part of Heat Doctor (https://github.com/NoahA6624/heat-doctor). Read-only: it only reports information as JSON.
# Checks the digital signature of each file path given on standard input (one per line).
$ErrorActionPreference = 'SilentlyContinue'
$paths = @($input | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
@($paths | ForEach-Object { $s = Get-AuthenticodeSignature -LiteralPath $_
  [pscustomobject]@{ path = $_; status = [string]$s.Status; signer = [string]$s.SignerCertificate.Subject } }) | ConvertTo-Json -Compress
