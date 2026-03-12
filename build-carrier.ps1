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

# Handle credentials
if ($VaultName -and $SecretName) {
    Write-Host "Fetching credentials from Azure Key Vault: $VaultName..." -ForegroundColor Cyan
    $password = az keyvault secret show --vault-name $VaultName --name $SecretName --query value -o tsv
    if (-not $password) {
        Write-Host "Failed to fetch secret from Key Vault!" -ForegroundColor Red
        exit 1
    }
    # Login via docker login for flexibility with tokens/SPs
    # Assuming the registry name is the username for token-based auth or '00000000-0000-0000-0000-000000000000' for SP
    $regName = ($Registry -replace '\.azurecr\.io$','')
    echo $password | docker login $Registry -u $regName --password-stdin
} else {
    Write-Host "Logging into ACR via az acr login..." -ForegroundColor Cyan
    az acr login --name ($Registry -replace '\.azurecr\.io$','')
}

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
