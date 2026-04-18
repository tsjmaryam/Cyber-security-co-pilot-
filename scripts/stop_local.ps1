[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$statePath = Join-Path $repoRoot ".local\services\local_services.json"

if (-not (Test-Path $statePath)) {
    Write-Output '{"stopped": [], "message": "No local service state file found."}'
    exit 0
}

$state = Get-Content -Path $statePath -Raw | ConvertFrom-Json
$stopped = @()

foreach ($service in $state.services) {
    if (-not $service.pid) {
        continue
    }

    $process = Get-Process -Id $service.pid -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        Stop-Process -Id $service.pid -Force
        $stopped += [ordered]@{
            name = $service.name
            pid = $service.pid
        }
    }
}

Remove-Item -Path $statePath -Force
([ordered]@{ stopped = $stopped }) | ConvertTo-Json -Depth 4
