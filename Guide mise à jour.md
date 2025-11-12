# 🛠️ Mise à jour de la base de données CVE

## Méthode automatique (recommandée)

Utilisez le script de mise à jour automatique :

**Sur Windows (PowerShell) :**
```powershell
.\update-database.ps1
```

**Sur Linux/Mac (Bash) :**
```bash
chmod +x update-database.sh
./update-database.sh
```

## Méthode manuelle

Si vous préférez faire les étapes manuellement :

1. **Éteindre l'application CVE**
   ```sh
   # Arrêter l'application si elle est en cours d'exécution
   ```

2. **Importer les nouvelles données**
   ```sh
   npm run import
   ```

3. **Redémarrer l'application CVE**
   ```sh
   node server.js 8080
   ```

> 💡 **Astuce :** Assurez-vous que l'importation est terminée avant de relancer l'application.





