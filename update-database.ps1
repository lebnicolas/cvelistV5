# Script PowerShell de mise à jour de la base de données CVE
# Usage: .\update-database.ps1

Write-Host "🔄 Mise à jour de la base de données CVE" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Récupérer les modifications depuis le dépôt Git original
Write-Host "1️⃣  Récupération des modifications depuis Git..." -ForegroundColor Yellow

# Vérifier si le remote upstream existe
$upstreamExists = git remote | Select-String -Pattern "upstream" -Quiet

if (-not $upstreamExists) {
    Write-Host "   ⚠️  Le remote 'upstream' n'est pas configuré" -ForegroundColor Yellow
    Write-Host "   ℹ️  Vous pouvez l'ajouter avec: git remote add upstream <URL>" -ForegroundColor Cyan
    Write-Host "   ⏭️  Passage à l'étape suivante..." -ForegroundColor Gray
} else {
    Write-Host "   📥 Récupération des modifications depuis upstream..." -ForegroundColor Gray
    git fetch upstream 2>$null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   🔀 Fusion des modifications..." -ForegroundColor Gray
        git merge upstream/main 2>$null
        $mergeStatus = $LASTEXITCODE
        
        if ($mergeStatus -ne 0) {
            git merge upstream/master 2>$null
            $mergeStatus = $LASTEXITCODE
        }
        
        if ($mergeStatus -eq 0) {
            Write-Host "   ✅ Modifications récupérées avec succès" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Conflits potentiels lors de la fusion. Vérifiez manuellement." -ForegroundColor Yellow
        }
    } else {
        Write-Host "   ⚠️  Erreur lors de la récupération Git. Continuons..." -ForegroundColor Yellow
    }
}

Write-Host ""

# 2. Arrêter l'application si elle est en cours d'exécution
Write-Host "2️⃣  Vérification de l'application en cours..." -ForegroundColor Yellow

$process = Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*server.js*"
}

if ($process) {
    Write-Host "   ⚠️  Application détectée (PID: $($process.Id))" -ForegroundColor Yellow
    $response = Read-Host "   Voulez-vous arrêter l'application ? (O/n)"
    if ($response -ne "n" -and $response -ne "N") {
        Write-Host "   🛑 Arrêt de l'application..." -ForegroundColor Yellow
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Host "   ✅ Application arrêtée" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Veuillez arrêter l'application manuellement avant de continuer" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "   ✅ Aucune application détectée" -ForegroundColor Green
}

Write-Host ""

# 3. Importer les nouvelles données
Write-Host "3️⃣  Import des nouvelles données dans SQLite..." -ForegroundColor Yellow
Write-Host "   ⏳ Cela peut prendre quelques minutes..." -ForegroundColor Gray

npm run import

if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✅ Import terminé avec succès" -ForegroundColor Green
} else {
    Write-Host "   ❌ Erreur lors de l'import" -ForegroundColor Red
    exit 1
}

Write-Host ""

# 4. Redémarrer l'application
Write-Host "4️⃣  Redémarrage de l'application..." -ForegroundColor Yellow
$response = Read-Host "   Voulez-vous redémarrer l'application maintenant ? (O/n)"
if ($response -ne "n" -and $response -ne "N") {
    Write-Host "   🚀 Démarrage de l'application sur le port 8080..." -ForegroundColor Yellow
    Start-Process -NoNewWindow -FilePath "node" -ArgumentList "server.js", "8080"
    Start-Sleep -Seconds 2
    Write-Host "   ✅ Application démarrée sur http://localhost:8080" -ForegroundColor Green
} else {
    Write-Host "   ℹ️  Vous pouvez démarrer l'application manuellement avec: node server.js 8080" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "✨ Mise à jour terminée !" -ForegroundColor Green

