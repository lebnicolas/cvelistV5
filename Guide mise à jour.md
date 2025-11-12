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

1. **Récupérer les modifications depuis le dépôt Git original**
   ```sh
   git fetch upstream
      ```
   
   > 💡 **Note :** Si vous n'avez pas encore configuré le remote `upstream`, ajoutez-le avec :
   > ```sh
   > git remote add upstream https://github.com/CVEProject/cvelistV5/tree/main
   > ```

2. **Éteindre l'application CVE**
   ```sh
   # Arrêter l'application si elle est en cours d'exécution
   ```

3. **Importer les nouvelles données dans SQLite**
   ```sh
   npm run import
   ```

4. **Redémarrer l'application CVE**
   ```sh
   node server.js 8080
   ```

> 💡 **Astuce :** Assurez-vous que l'importation est terminée avant de relancer l'application.





