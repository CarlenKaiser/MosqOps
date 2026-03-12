# Build and push the MosqOps plugin carrier image
# Usage: .\build-carrier.ps1 [-Registry <acr>] [-Tag <version>]
param(
    [string]$Registry = "usiotreporting.azurecr.io",
    [string]$Tag = "latest",
    [string]$ImageName = "mosqops-plugin"
)

$ErrorActionPreference = "Stop"
$FullImage = "$Registry/${ImageName}:${Tag}"

Write-Host "Building MosqOps plugin carrier image..." -ForegroundColor Cyan
Write-Host "  Image: $FullImage" -ForegroundColor Gray

# Build the carrier image (multi-stage: compile + minimal carrier)
docker build -f Dockerfile.carrier -t $FullImage .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Build successful. Pushing to ACR..." -ForegroundColor Green

# Login to ACR (assumes az login has been done)
az acr login --name ($Registry -replace '\.azurecr\.io$','')
docker push $FullImage

if ($LASTEXITCODE -ne 0) {
    Write-Host "Push failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Successfully published: $FullImage" -ForegroundColor Green
