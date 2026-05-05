# Docker Compose startup script (PowerShell)
# Usage: .\docker-run.ps1 <target_name> [output_path]
# Compatible with Docker Compose V1 and V2

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "./output",
    
    [Parameter(Mandatory=$false)]
    [string]$StartTime,
    
    [Parameter(Mandatory=$false)]
    [string]$EndTime
)

# Convert relative path to absolute path
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Check directory permissions
try {
    $testFile = Join-Path $OutputPath ".write_test"
    [System.IO.File]::WriteAllText($testFile, "test")
    Remove-Item $testFile -Force
} catch {
    Write-Host "Warning: Output directory '$OutputPath' may not be writable" -ForegroundColor Yellow
}

Write-Host "Starting Docker Compose..."
Write-Host "Target: $TargetName"
Write-Host "Output: $OutputPath (mapped to /app/output in container)"
if ($StartTime) {
    Write-Host "Start Time: $StartTime"
}
if ($EndTime) {
    Write-Host "End Time: $EndTime"
}

# Detect available Docker Compose command
# Prefer V2 (docker compose), fallback to V1 (docker-compose)
$composeCmd = $null
try {
    # Try Docker Compose V2 (as Docker CLI plugin)
    $composeV2 = docker compose version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Using Docker Compose V2..."
        $composeCmd = { docker compose $args }
    } else {
        throw "V2 not available"
    }
} catch {
    # Fallback to Docker Compose V1 (standalone command)
    try {
        $composeV1 = docker-compose version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Using Docker Compose V1..."
            $composeCmd = { docker-compose $args }
        } else {
            throw "V1 not available"
        }
    } catch {
        Write-Host "Error: Docker Compose not found. Please install Docker Compose V1 or V2." -ForegroundColor Red
        exit 1
    }
}

# Start Tor service first (run in background)
Write-Host "Starting Tor service..."
& $composeCmd up -d tor_docker

# Wait for Tor service health check to pass
Write-Host "Waiting for Tor service to be ready..."
$timeout = 60
$elapsed = 0
$torReady = $false
while ($elapsed -lt $timeout) {
    $status = & $composeCmd ps tor_docker 2>&1
    if ($status -match "healthy") {
        Write-Host "Tor service is ready"
        $torReady = $true
        break
    }
    Start-Sleep -Seconds 2
    $elapsed += 2
}

if (-not $torReady) {
    Write-Host "Warning: Tor service health check timeout, but continuing..." -ForegroundColor Yellow
}

# Run main container with dynamic volume mapping
Write-Host "Running main program..."
$HostOutputPath = $OutputPath  # Save host path
Write-Host "Volume mapping: $HostOutputPath -> /app/output"
$env:TARGET_NAME = $TargetName
$env:OUTPUT_PATH = "/app/output"  # Container path
if ($StartTime) {
    $env:START_TIME = $StartTime
}
if ($EndTime) {
    $env:END_TIME = $EndTime
}
& $composeCmd run --rm --volume "${HostOutputPath}:/app/output" main

# Verify files have been saved
Write-Host ""
Write-Host "Checking output files..."
$outputDir = Join-Path $HostOutputPath $TargetName
if (Test-Path $outputDir) {
    Write-Host "✓ Found output directory: $outputDir" -ForegroundColor Green
    $csvFiles = Get-ChildItem -Path $outputDir -Filter "*.csv" -ErrorAction SilentlyContinue
    $fileCount = ($csvFiles | Measure-Object).Count
    Write-Host "✓ Found $fileCount CSV file(s)" -ForegroundColor Green
    Get-ChildItem -Path $outputDir | Format-Table -AutoSize
} else {
    Write-Host "✗ Output directory not found: $outputDir" -ForegroundColor Red
    Write-Host "Please check container logs for more information"
    Write-Host "Attempting to list output directory contents:"
    Get-ChildItem -Path $HostOutputPath -ErrorAction SilentlyContinue | Format-Table -AutoSize
}

# Cleanup: Stop and remove Tor container
Write-Host "Cleaning up Tor service..."
& $composeCmd stop tor_docker 2>&1 | Out-Null
& $composeCmd rm -f tor_docker 2>&1 | Out-Null

Write-Host "Done!"
