#!/bin/bash

# Script de mise à jour de la base de données CVE
# Usage: ./update-database.sh

set -e  # Arrêter en cas d'erreur

echo "🔄 Mise à jour de la base de données CVE"
echo "=========================================="
echo ""

# 1. Arrêter l'application si elle est en cours d'exécution
echo "1️⃣  Vérification de l'application en cours..."
if lsof -ti:8080 > /dev/null 2>&1 || pgrep -f "node server.js" > /dev/null 2>&1; then
    echo "   ⚠️  Application détectée sur le port 8080"
    read -p "   Voulez-vous arrêter l'application ? (o/N) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Oo]$ ]]; then
        echo "   🛑 Arrêt de l'application..."
        pkill -f "node server.js" || true
        sleep 2
        echo "   ✅ Application arrêtée"
    else
        echo "   ⚠️  Veuillez arrêter l'application manuellement avant de continuer"
        exit 1
    fi
else
    echo "   ✅ Aucune application détectée"
fi

echo ""

# 2. Importer les nouvelles données
echo "2️⃣  Import des nouvelles données dans SQLite..."
echo "   ⏳ Cela peut prendre quelques minutes..."
npm run import

if [ $? -eq 0 ]; then
    echo "   ✅ Import terminé avec succès"
else
    echo "   ❌ Erreur lors de l'import"
    exit 1
fi

echo ""

# 3. Redémarrer l'application
echo "3️⃣  Redémarrage de l'application..."
read -p "   Voulez-vous redémarrer l'application maintenant ? (O/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo "   🚀 Démarrage de l'application sur le port 8080..."
    node server.js 8080 &
    sleep 2
    echo "   ✅ Application démarrée sur http://localhost:8080"
else
    echo "   ℹ️  Vous pouvez démarrer l'application manuellement avec: node server.js 8080"
fi

echo ""
echo "✨ Mise à jour terminée !"

