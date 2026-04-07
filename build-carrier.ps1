# Build and push the MosqOps plugin carrier image (multi-arch by default)
# Usage examples:
#   .\build-carrier.ps1
#   .\build-carrier.ps1 -Registry ghcr.io -Repository carlenkaiser/mosqops-plugin -Tag v0.1.0
#   .\build-carrier.ps1 -Registry ghcr.io -Repository carlenkaiser/mosqops-plugin -Tag v0.1.0 -Username <github-user> -Password <github-token>
param(
    [string]$Registry = "ghcr.io",
    [string]$Repository = "carlenkaiser/mosqops-plugin",
    [string]$Tag = "latest",
    [string]$Platforms = "linux/amd64,linux/arm64",
    [string]$BuilderName = "mosqops-multiarch",
    [string]$CacheRef = "",
    [ValidateSet("auto", "acr", "ghcr", "none")]
    [string]$AuthMode = "auto",
    [string]$Username = "",
    [string]$Password = ""
)

$ErrorActionPreference = "Stop"
$Repository = $Repository.Trim('/').ToLowerInvariant()
$FullImage = "$Registry/$Repository`:`$Tag"

if (-not $CacheRef) {
    $CacheRef = "$Registry/$Repository:buildcache"
}

if ($AuthMode -eq "auto") {
    if ($Registry -match '\.azurecr\.io$') {
        $AuthMode = "acr"
    } elseif ($Registry -eq "ghcr.io") {
        $AuthMode = "ghcr"
    } else {
        $AuthMode = "none"
    }
}

Write-Host "Building MosqOps plugin carrier image..." -ForegroundColor Cyan
Write-Host "  Image: $FullImage" -ForegroundColor Gray
Write-Host "  Platforms: $Platforms" -ForegroundColor Gray
Write-Host "  CacheRef: $CacheRef" -ForegroundColor Gray
Write-Host "  AuthMode: $AuthMode" -ForegroundColor Gray

switch ($AuthMode) {
    "acr" {
        $acrName = ($Registry -replace '\.azurecr\.io$', '')
        Write-Host "Authenticating Docker with ACR: $acrName" -ForegroundColor Cyan
        $acrToken = az acr login --name $acrName --expose-token --output tsv --query accessToken
        if (-not $acrToken) {
            Write-Host "Failed to get ACR access token!" -ForegroundColor Red
            exit 1
        }

        $acrToken | docker login $Registry --username 00000000-0000-0000-0000-000000000000 --password-stdin
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Docker login to ACR failed!" -ForegroundColor Red
            exit 1
        }
    }
    "ghcr" {
        if (-not $Username) {
            if ($env:GITHUB_ACTOR) {
                $Username = $env:GITHUB_ACTOR
            } elseif ($env:GHCR_USERNAME) {
                $Username = $env:GHCR_USERNAME
            }
        }

        if (-not $Password) {
            if ($env:GITHUB_TOKEN) {
                $Password = $env:GITHUB_TOKEN
            } elseif ($env:GHCR_TOKEN) {
                $Password = $env:GHCR_TOKEN
            }
        }

        if (-not $Username -or -not $Password) {
            Write-Host "GHCR auth requires username and token." -ForegroundColor Red
            Write-Host "Provide -Username/-Password or set GITHUB_ACTOR + GITHUB_TOKEN (or GHCR_USERNAME + GHCR_TOKEN)." -ForegroundColor Yellow
            exit 1
        }

        Write-Host "Authenticating Docker with GHCR as $Username" -ForegroundColor Cyan
        $Password | docker login $Registry --username $Username --password-stdin
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Docker login to GHCR failed!" -ForegroundColor Red
            exit 1
        }
    }
    "none" {
        Write-Host "Skipping registry authentication (AuthMode=none)." -ForegroundColor Yellow
    }
}

Write-Host "Ensuring buildx builder '$BuilderName' exists..." -ForegroundColor Cyan
$existingBuilder = docker buildx ls 2>$null | Select-String -Pattern "^$BuilderName\b"
if (-not $existingBuilder) {
    docker buildx create --name $BuilderName --driver docker-container --use | Out-Null
} else {
    docker buildx use $BuilderName | Out-Null
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to create/select buildx builder '$BuilderName'." -ForegroundColor Red
    exit 1
}

# Bootstrap builder so multi-platform emulation is ready.
docker buildx inspect --bootstrap | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to bootstrap buildx builder." -ForegroundColor Red
    exit 1
}

Write-Host "Building and pushing multi-arch image manifest..." -ForegroundColor Cyan
docker buildx build `
    --platform $Platforms `
    -f Dockerfile.carrier `
    -t $FullImage `
    --cache-from type=registry,ref=$CacheRef `
    --cache-to type=registry,ref=$CacheRef,mode=max `
    --push `
    .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Push failed for $FullImage" -ForegroundColor Red
    exit 1
}

if ($Tag -ne "latest") {
    $LatestImage = "$Registry/$Repository:latest"
    Write-Host "Also publishing latest tag as multi-arch: $LatestImage" -ForegroundColor Cyan
    docker buildx build `
        --platform $Platforms `
        -f Dockerfile.carrier `
        -t $LatestImage `
        --cache-from type=registry,ref=$CacheRef `
        --cache-to type=registry,ref=$CacheRef,mode=max `
        --push `
        .

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Push failed for $LatestImage" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Successfully published: $FullImage" -ForegroundColor Green
