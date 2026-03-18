# Build and push the MosqOps plugin carrier image
# Usage: .\build-carrier.ps1 [-Registry <acr>] [-Tag <version>] [-VaultName <vault>] [-SecretName <secret>]
param(
    [string]$Registry = "acriotdevcci.azurecr.io",
    [string]$Tag = "latest",
    [string]$ImageName = "mosqops-plugin",
    [string]$VaultName,
    [string]$SecretName
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

Write-Host "Build successful. Preparing to push to $Registry..." -ForegroundColor Green


# Always use az acr login --expose-token and docker login for ACR authentication
$acrName = ($Registry -replace '\.azurecr\.io$','')
Write-Host "Authenticating Docker with ACR: $acrName" -ForegroundColor Cyan
$acrToken = az acr login --name $acrName --expose-token --output tsv --query accessToken
if (-not $acrToken) {
    Write-Host "Failed to get ACR access token!" -ForegroundColor Red
    exit 1
}
echo $acrToken | docker login $Registry --username 00000000-0000-0000-0000-000000000000 --password-stdin

docker push $FullImage

if ($Tag -ne "latest") {
    $LatestImage = "$Registry/${ImageName}:latest"
    Write-Host "Tagging and pushing as latest: $LatestImage" -ForegroundColor Cyan
    docker tag $FullImage $LatestImage
    docker push $LatestImage
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "Push failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Successfully published: $FullImage" -ForegroundColor Green
