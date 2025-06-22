$ErrorActionPreference = "Stop"

# Configuration
$ProjectName = "rustreaper"
$OutputDir = "target\release"
$PackageDir = "dist"
$WebDir = "web"
$RulesDir = "rules"
$Version = (Get-Content Cargo.toml | Select-String '^version\s*=\s*"([^"]+)"').Matches.Groups[1].Value
$ArchiveName = "$ProjectName-$Version-windows.zip"

# Function to check for dependencies
function Check-Dependencies {
    Write-Host "Checking dependencies..."
    if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
        Write-Error "Rust is not installed. Please install it from https://www.rust-lang.org/tools/install"
        exit 1
    }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Error "Cargo is not installed. Please install Rust from https://www.rust-lang.org/tools/install"
        exit 1
    }
    if (-not (Test-Path (Join-Path $env:ProgramFiles "SQLite"))) {
        Write-Warning "SQLite not found. Attempting to install via winget..."
        winget install SQLite.SQLite
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to install SQLite. Please install manually."
            exit 1
        }
    }
}

# Function to clean build artifacts
function Clean-Build {
    Write-Host "Cleaning build artifacts..."
    if (Test-Path $OutputDir) { Remove-Item -Recurse -Force $OutputDir }
    if (Test-Path $PackageDir) { Remove-Item -Recurse -Force $PackageDir }
    cargo clean
}

# Function to build project
function Build-Project {
    Write-Host "Building $ProjectName (v$Version)..."
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed."
        exit 1
    }
}

# Function to run tests
function Run-Tests {
    Write-Host "Running tests..."
    cargo test
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Tests failed."
        exit 1
    }
}

# Function to verify YARA rules
function Verify-Yara-Rules {
    Write-Host "Verifying YARA rules..."
    $rulesFile = Join-Path $RulesDir "rules.yara"
    if (-not (Test-Path $rulesFile)) {
        Write-Error "YARA rules file not found at $rulesFile"
        exit 1
    }
    # Placeholder: Use cargo to run a YARA validation check
    cargo run --quiet -- verify-yara $rulesFile
    if ($LASTEXITCODE -ne 0) {
        Write-Error "YARA rules verification failed."
        exit 1
    }
}

# Function to generate sample memory dump
function Generate-Sample-Dump {
    Write-Host "Generating sample memory dump..."
    $dumpFile = Join-Path $PackageDir "sample_dump.bin"
    $sampleData = [byte[]]::new(0x1000) # 4KB of random data
    Get-Random -SetSeed 42 -Minimum 0 -Maximum 256 -Count 0x1000 | ForEach-Object { $sampleData[$_] = $_ }
    [System.IO.File]::WriteAllBytes($dumpFile, $sampleData)
}

# Function to package release
function Package-Release {
    Write-Host "Packaging release..."
    New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null
    Copy-Item -Path (Join-Path $OutputDir "$ProjectName.exe") -Destination $PackageDir
    Copy-Item -Path $WebDir -Destination (Join-Path $PackageDir $WebDir) -Recurse -Force
    Copy-Item -Path $RulesDir -Destination (Join-Path $PackageDir $RulesDir) -Recurse -Force
    New-Item -Path (Join-Path $PackageDir "db") -ItemType Directory -Force | Out-Null
    Generate-Sample-Dump

    # Create zip archive
    Compress-Archive -Path (Join-Path $PackageDir "*") -DestinationPath (Join-Path $PackageDir $ArchiveName) -Force
    Write-Host "Release packaged at: $(Join-Path $PackageDir $ArchiveName)"
}

# Main execution
if ($args[0] -eq "--clean") {
    Clean-Build
    exit 0
}

Write-Host "Starting build for $ProjectName (v$Version) on Windows"
Check-Dependencies
Build-Project
Run-Tests
Verify-Yara-Rules
Package-Release

Write-Host "Build and packaging completed successfully!"