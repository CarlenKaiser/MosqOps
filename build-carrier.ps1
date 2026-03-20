# Build and push the MosqOps plugin carrier image (multi-arch by default)
# Usage: .\build-carrier.ps1 [-Registry <acr>] [-Tag <version>] [-Platforms <linux/amd64,linux/arm64>]
param(
    [string]$Registry = "acriotdevcci.azurecr.io",
    [string]$Tag = "latest",
    [string]$ImageName = "mosqops-plugin",
    [string]$Platforms = "linux/amd64,linux/arm64",
    [string]$BuilderName = "mosqops-multiarch"
)

$ErrorActionPreference = "Stop"
$FullImage = "$Registry/${ImageName}:${Tag}"

Write-Host "Building MosqOps plugin carrier image..." -ForegroundColor Cyan
Write-Host "  Image: $FullImage" -ForegroundColor Gray
Write-Host "  Platforms: $Platforms" -ForegroundColor Gray

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

# Always use az acr login --expose-token and docker login for ACR authentication
$acrName = ($Registry -replace '\.azurecr\.io$','')
Write-Host "Authenticating Docker with ACR: $acrName" -ForegroundColor Cyan
$acrToken = az acr login --name $acrName --expose-token --output tsv --query accessToken
if (-not $acrToken) {
    Write-Host "Failed to get ACR access token!" -ForegroundColor Red
    exit 1
}
echo $acrToken | docker login $Registry --username 00000000-0000-0000-0000-000000000000 --password-stdin

Write-Host "Ensuring buildx builder '$BuilderName' exists..." -ForegroundColor Cyan
$existingBuilder = docker buildx ls 2>$null | Select-String -Pattern "^$BuilderName\b"
if (-not $existingBuilder) {
    docker buildx create --name $BuilderName --driver docker-container --use | Out-Null
} else {
    docker buildx use $BuilderName | Out-Null
}

# Bootstrap builder so multi-platform emulation is ready.
docker buildx inspect --bootstrap | Out-Null

Write-Host "Building and pushing multi-arch image manifest..." -ForegroundColor Cyan
docker buildx build \
    --platform $Platforms \
    -f Dockerfile.carrier \
    -t $FullImage \
    --push \
    .

if ($Tag -ne "latest") {
    $LatestImage = "$Registry/${ImageName}:latest"
    Write-Host "Also publishing latest tag as multi-arch: $LatestImage" -ForegroundColor Cyan
    docker buildx build \
        --platform $Platforms \
        -f Dockerfile.carrier \
        -t $LatestImage \
        --push \
        .
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "Push failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Successfully published: $FullImage" -ForegroundColor Green
