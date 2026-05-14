#Requires -Version 5.1
<#
.SYNOPSIS
    Sets up SAGE on Windows. Requires WSL with Ubuntu for building FlexFringe.
.DESCRIPTION
    Installs Graphviz, Python packages, builds FlexFringe via WSL, and decompresses alert files.
#>

$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot

function ConvertTo-WslPath($winPath) {
    $abs = [System.IO.Path]::GetFullPath($winPath)
    $drive = $abs[0].ToString().ToLower()
    $rest = $abs.Substring(2) -replace '\\', '/'
    return "/mnt/$drive$rest"
}

Set-Location $ProjectDir

Write-Host "=== Installing Graphviz ===" -ForegroundColor Cyan
$dotPath = "C:\Program Files\Graphviz\bin\dot.exe"
if (Test-Path $dotPath) {
    Write-Host "Graphviz already installed."
} else {
    winget install graphviz.graphviz --silent
}
$graphvizBin = "C:\Program Files\Graphviz\bin"
$userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notmatch 'Graphviz') {
    [System.Environment]::SetEnvironmentVariable("Path", $userPath + ";" + $graphvizBin, "User")
    Write-Host "Added Graphviz to user PATH (restart terminal to take effect)."
}

Write-Host "=== Installing Python packages ===" -ForegroundColor Cyan
pip install -r requirements.txt

Write-Host "=== Building FlexFringe via WSL ===" -ForegroundColor Cyan
$ffBinary = Join-Path $ProjectDir "FlexFringe\flexfringe"
if (Test-Path $ffBinary) {
    Write-Host "FlexFringe binary already exists, skipping build."
} else {
    wsl -d Ubuntu -- echo "WSL check" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Ubuntu WSL distro not available. Install it with: wsl --install -d Ubuntu"
        exit 1
    }

    $wslProjectDir = ConvertTo-WslPath $ProjectDir

    # Write the build script to a temp file (avoids PowerShell escaping issues in here-strings)
    $tmpScript = Join-Path $env:TEMP "sage_ff_build.sh"
    $buildScript = @'
#!/usr/bin/env bash
set -e
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cmake g++ libboost-all-dev git
TMP_FF=$(mktemp -d)
trap "rm -rf $TMP_FF" EXIT
git clone --quiet https://github.com/tudelft-cda-lab/FlexFringe "$TMP_FF"
cmake -S "$TMP_FF" -B "$TMP_FF/build" -DCMAKE_BUILD_TYPE=Release -Wno-dev > /dev/null
cmake --build "$TMP_FF/build" --parallel "$(nproc)"
cp "$TMP_FF/build/flexfringe" "WSLPROJECTDIR/FlexFringe/flexfringe"
echo "FlexFringe built successfully."
'@
    # Substitute the project dir and ensure Unix line endings
    $buildScript = $buildScript -replace 'WSLPROJECTDIR', $wslProjectDir
    [System.IO.File]::WriteAllText($tmpScript, ($buildScript -replace "`r`n", "`n"), [System.Text.Encoding]::UTF8)

    $wslTmpScript = ConvertTo-WslPath $tmpScript
    New-Item -ItemType Directory -Force "FlexFringe" | Out-Null

    Write-Host "Installing build tools and compiling FlexFringe (this takes several minutes)..."
    wsl -d Ubuntu -- bash "$wslTmpScript"
    Remove-Item $tmpScript -Force
}

Write-Host "=== Setting up FlexFringe config ===" -ForegroundColor Cyan
New-Item -ItemType Directory -Force "FlexFringe\ini" | Out-Null
Copy-Item "spdfa-config.ini" "FlexFringe\ini\spdfa-config.ini" -Force

Write-Host "=== Decompressing alert files ===" -ForegroundColor Cyan
Add-Type -AssemblyName System.IO.Compression.FileSystem
Get-ChildItem "alerts" -Recurse -Filter "*.gz" | ForEach-Object {
    $outPath = $_.FullName -replace '\.gz$', ''
    if (-not (Test-Path $outPath)) {
        $in = [System.IO.File]::OpenRead($_.FullName)
        $gz = [System.IO.Compression.GZipStream]::new($in, [System.IO.Compression.CompressionMode]::Decompress)
        $out = [System.IO.File]::Create($outPath)
        $gz.CopyTo($out)
        $out.Close(); $gz.Close(); $in.Close()
        Write-Host "  Decompressed: $($_.Name)"
    }
}

Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Green
Write-Host "Run SAGE with:"
Write-Host "  python sage.py alerts/cptc-2017/ exp-2017 --dataset cptc"
Write-Host "  python sage.py alerts/cptc-2018/ exp-2018 -t 2.0 -w 200 --dataset cptc"
Write-Host "  python sage.py alerts/ccdc/ exp-ccdc --dataset other --keep-files"
