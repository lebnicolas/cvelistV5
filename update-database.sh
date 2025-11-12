#!/bin/bash

# Script de mise à jour de la base de données CVE
# Usage: ./update-database.sh

set -e  # Arrêter en cas d'erreur

echo "🔄 Mise à jour de la base de données CVE"
echo "=========================================="
echo ""

# 1. Récupérer les modifications depuis le dépôt Git original
echo "1️⃣  Récupération des modifications depuis Git..."

# Vérifier si le remote upstream existe
if git remote | grep -q "upstream"; then
    echo "   📥 Récupération des modifications depuis upstream..."
    set +e  # Désactiver temporairement set -e pour gérer les erreurs Git
    git fetch upstream
    fetch_status=$?
    set -e  # Réactiver set -e
    
    if [ $fetch_status -eq 0 ]; then
        echo "   🔀 Fusion des modifications..."
        set +e  # Désactiver temporairement set -e
        git merge upstream/main 2>/dev/null
        merge_status=$?
        if [ $merge_status -ne 0 ]; then
            git merge upstream/master 2>/dev/null
            merge_status=$?
        fi
        set -e  # Réactiver set -e
        
        if [ $merge_status -eq 0 ]; then
            echo "   ✅ Modifications récupérées avec succès"
        else
            echo "   ⚠️  Conflits potentiels lors de la fusion. Vérifiez manuellement."
        fi
    else
        echo "   ⚠️  Erreur lors de la récupération Git. Continuons..."
    fi
else
    echo "   ⚠️  Le remote 'upstream' n'est pas configuré"
    echo "   ℹ️  Vous pouvez l'ajouter avec: git remote add upstream <URL>"
    echo "   ⏭️  Passage à l'étape suivante..."
fi

echo ""

# 2. Arrêter l'application si elle est en cours d'exécution
echo "2️⃣  Vérification de l'application en cours..."
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

# 3. Importer les nouvelles données
echo "3️⃣  Import des nouvelles données dans SQLite..."
echo "   ⏳ Cela peut prendre quelques minutes..."
npm run import

if [ $? -eq 0 ]; then
    echo "   ✅ Import terminé avec succès"
else
    echo "   ❌ Erreur lors de l'import"
    exit 1
fi

echo ""

# 4. Redémarrer l'application
echo "4️⃣  Redémarrage de l'application..."
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

