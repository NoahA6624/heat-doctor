# Part of Heat Doctor (https://github.com/NoahA6624/heat-doctor). Read-only: it only reports information as JSON.
# Antivirus status, Defender detections and non-Microsoft scheduled tasks.
$ErrorActionPreference = 'SilentlyContinue'
$mp = $null
try { $s = Get-MpComputerStatus -ErrorAction Stop
  $mp = [pscustomobject]@{ service = $s.AMServiceEnabled; realtime = $s.RealTimeProtectionEnabled
    sig_age = $s.AntivirusSignatureAge; quick_age = $s.QuickScanAge; full_age = $s.FullScanAge
    tamper = $s.IsTamperProtected } } catch {}
$av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
  ForEach-Object { [pscustomobject]@{ name = $_.displayName; state = $_.productState } })
$threats = @()
try { $threats = @(Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 10 |
  ForEach-Object { [pscustomobject]@{ id = [string]$_.ThreatID; time = [string]$_.InitialDetectionTime; resources = ($_.Resources -join '; ') } }) } catch {}
$tasks = @(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } |
  ForEach-Object { $t = $_; $t.Actions | Where-Object { $_.Execute } | ForEach-Object {
    [pscustomobject]@{ name = $t.TaskName; path = $t.TaskPath; author = [string]$t.Author; exec = [string]$_.Execute; args = [string]$_.Arguments } } })
[pscustomobject]@{ defender = $mp; av = $av; threats = $threats; tasks = $tasks } | ConvertTo-Json -Depth 4 -Compress
