param(
    [string]$Filter,
    [switch]$FullSuite
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$zmqHeader = Join-Path $PSScriptRoot "zmq-windows-no-ipc.h"
$bitcoinExe = Join-Path $repoRoot "bin\bitcoin-28.1\bin\bitcoind.exe"
$bitcoinArchive = Join-Path $repoRoot "bin\bitcoin-28.1-win64.zip"

if ($Filter -and $FullSuite) {
    throw "Use either -Filter or -FullSuite, not both."
}

# The test framework otherwise downloads Bitcoin Core when its cached binary
# is missing. Require the local archive in that case so this helper stays offline.
if (-not (Test-Path $bitcoinExe)) {
    if (-not (Test-Path $bitcoinArchive)) {
        throw "Missing local Bitcoin Core 28.1 binary and archive; refusing the test framework's download fallback."
    }
    $env:BITCOIND_TARBALL_FILE = $bitcoinArchive
}

# Keep dependency resolution offline as well as the test daemons.
$env:CARGO_NET_OFFLINE = "true"

$needsElectrs = $FullSuite -or -not $Filter -or $Filter -match "electrum"
if ($needsElectrs -and ([string]::IsNullOrWhiteSpace($env:ELECTRS_EXEC) -or -not (Test-Path -LiteralPath $env:ELECTRS_EXEC))) {
    throw "Set ELECTRS_EXEC to a local electrs executable for the focused default tests, Electrum filters, or -FullSuite."
}

# zeromq-src enables Windows IPC in its bundled libzmq build. This project
# uses TCP endpoints only; undefining the IPC feature avoids a Windows poller
# crash in libzmq 4.3.4. CXXFLAGS is inherited only by this script's process.
$env:CXXFLAGS = "/FI$zmqHeader"
$env:OPENSWAP_TEST_LOG = "info"

Push-Location $repoRoot
try {
    if ($FullSuite) {
        cargo test --features integration-test -- --nocapture --test-threads=2
        $testExitCode = $LASTEXITCODE
    }
    elseif ($Filter) {
        cargo test --features integration-test --test integration $Filter -- --nocapture --test-threads=2
        $testExitCode = $LASTEXITCODE
    }
    else {
        $focusedTests = @(
            "standard_swap::test_standard_openswap",
            "taproot_swap::test_taproot_openswap",
            "electrum_swap::test_legacy_openswap_electrum",
            "electrum_swap::test_taproot_openswap_electrum"
        )
        $testExitCode = 0
        foreach ($testName in $focusedTests) {
            cargo test --features integration-test --test integration $testName -- --exact --nocapture --test-threads=1
            if ($LASTEXITCODE -ne 0) {
                $testExitCode = $LASTEXITCODE
                break
            }
        }
    }
}
finally {
    Pop-Location
}

exit $testExitCode
