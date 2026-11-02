# Windows port of `make coverage`: runs tests and enforces the coverage gate.
param([double]$Minimum = 90)
$ErrorActionPreference = 'Stop'

# Quoted: Windows PowerShell 5.1 splits -flag=name.ext into two arguments.
go test -count=1 -covermode=atomic '-coverprofile=coverage.out' ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$line = go tool cover '-func=coverage.out' | Select-String '^total:'
$percent = [double](($line.ToString() -split '\s+')[-1].TrimEnd('%'))
if ($percent -lt $Minimum) {
    Write-Error "Coverage $percent% is below required $Minimum%"
    exit 1
}
Write-Host "Coverage $percent% meets required $Minimum%"
