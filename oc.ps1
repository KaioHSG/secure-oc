#!/usr/bin/env pwsh
# secure-oc launcher for PowerShell. Runs the Python implementation.
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$scriptDir;$env:PYTHONPATH" } else { $scriptDir }

$python = $null
foreach ($candidate in @('python', 'python3', 'py')) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) { $python = $cmd.Source; break }
}

if (-not $python) {
    Write-Error "secure-oc: Python not found in PATH"
    exit 1
}

& $python -m secure_oc @args
exit $LASTEXITCODE
