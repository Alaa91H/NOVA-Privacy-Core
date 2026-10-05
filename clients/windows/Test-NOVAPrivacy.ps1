param(
    [string]$ExpectedDns = "10.77.0.1",
    [string]$ExpectedAdapter = ""
)

$ErrorActionPreference = "Stop"
$failed = $false

function Pass([string]$Message) { Write-Host "PASS  $Message" }
function Fail([string]$Message) { Write-Host "FAIL  $Message" -ForegroundColor Red; $script:failed = $true }
function Warn([string]$Message) { Write-Host "WARN  $Message" -ForegroundColor Yellow }

$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" |
    Sort-Object RouteMetric, InterfaceMetric

if (-not $routes) {
    Fail "No IPv4 default route"
} elseif ($ExpectedAdapter) {
    $ok = $routes | Where-Object { $_.InterfaceAlias -eq $ExpectedAdapter }
    if ($ok) { Pass "Expected protected adapter participates in IPv4 routing: $ExpectedAdapter" }
    else { Fail "Expected protected adapter not found in IPv4 default routes: $ExpectedAdapter" }
} else {
    Warn ("Set -ExpectedAdapter to enforce adapter identity. Current IPv4 defaults: " +
        (($routes | Select-Object -ExpandProperty InterfaceAlias -Unique) -join ", "))
}

$v6 = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0" -ErrorAction SilentlyContinue
if ($v6) {
    if ($ExpectedAdapter -and ($v6 | Where-Object { $_.InterfaceAlias -ne $ExpectedAdapter })) {
        Fail "A non-NOVA IPv6 default route exists"
    } else {
        Warn "IPv6 default route exists; confirm it is tunneled"
    }
} else {
    Pass "No IPv6 default route (fail-closed IPv6 mode)"
}

$dns = Get-DnsClientServerAddress -AddressFamily IPv4 |
    ForEach-Object { $_.ServerAddresses } |
    Where-Object { $_ }

if ($dns -contains $ExpectedDns) {
    Pass "NOVA DNS address $ExpectedDns is configured"
} else {
    Fail "Expected NOVA DNS $ExpectedDns not found"
}

Write-Host ""
Write-Host "No third-party public-IP service was contacted."
Write-Host "For tunnel-failure acceptance, stop AWG from Oracle Console and verify"
Write-Host "Windows cannot reach any Internet destination until the tunnel returns."

if ($failed) { exit 1 }
exit 0
