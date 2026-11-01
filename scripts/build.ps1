# Windows port of `make build`: builds http_ssh_proxy.exe with embedded version info.
$ErrorActionPreference = 'Stop'

$version = (Get-Content VERSION -Raw).Trim()
if (-not $version) { $version = 'dev' }
elseif (-not $version.StartsWith('v')) { $version = "v$version" }

$commit = git rev-parse --short=12 HEAD 2>$null
if (-not $commit) { $commit = 'unknown' }

$buildTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$pkg = 'github.com/hightemp/http_ssh_proxy/internal/buildinfo'
$ldflags = "-X $pkg.Version=$version -X $pkg.Commit=$commit -X $pkg.BuildTime=$buildTime"

go build -trimpath -ldflags $ldflags -o http_ssh_proxy.exe -v ./cmd/http_ssh_proxy
exit $LASTEXITCODE
