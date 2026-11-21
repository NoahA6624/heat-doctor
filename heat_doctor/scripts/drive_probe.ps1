# Part of Heat Doctor (https://github.com/NoahA6624/heat-doctor). Read-only: it only reports information as JSON.
# Drive model, health, temperature (temperature needs administrator rights) and the active power plan.
$ErrorActionPreference = 'SilentlyContinue'
$drives = @(Get-PhysicalDisk | ForEach-Object {
  $r = $null
  try { $r = $_ | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
  [pscustomobject]@{
    name = $_.FriendlyName; media = [string]$_.MediaType; bus = [string]$_.BusType
    size = [int64]$_.Size; health = [string]$_.HealthStatus
    temp = $r.Temperature; temp_max = $r.TemperatureMax; wear = $r.Wear
    hours = $r.PowerOnHours; read_errors = $r.ReadErrorsTotal; write_errors = $r.WriteErrorsTotal
  }
})
[pscustomobject]@{ drives = $drives; plan = ((powercfg /getactivescheme) -join ' ') } | ConvertTo-Json -Depth 4 -Compress
