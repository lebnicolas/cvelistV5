# Script PowerShell de mise à jour de la base de données CVE
# Usage: .\update-database.ps1

Write-Host "🔄 Mise à jour de la base de données CVE" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Arrêter l'application si elle est en cours d'exécution
Write-Host "1️⃣  Vérification de l'application en cours..." -ForegroundColor Yellow

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

# 2. Importer les nouvelles données
Write-Host "2️⃣  Import des nouvelles données dans SQLite..." -ForegroundColor Yellow
Write-Host "   ⏳ Cela peut prendre quelques minutes..." -ForegroundColor Gray

npm run import

if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✅ Import terminé avec succès" -ForegroundColor Green
} else {
    Write-Host "   ❌ Erreur lors de l'import" -ForegroundColor Red
    exit 1
}

Write-Host ""

# 3. Redémarrer l'application
Write-Host "3️⃣  Redémarrage de l'application..." -ForegroundColor Yellow
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

