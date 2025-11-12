/**
 * Chargeur de fichiers CVE
 * Parcourt le dossier cves/2025/ et charge tous les fichiers JSON
 */

const CVE_LOADER = {
    basePath: 'cves/2025',
    cveIndex: [],
    cveCache: new Map(),
    loading: false,
    
    /**
     * Met à jour le statut de chargement (pour compatibilité avec app.js)
     */
    updateLoadingStatus(status) {
        // Cette méthode sera appelée depuis app.js si disponible
        if (window.APP && window.APP.updateLoadingStatus) {
            window.APP.updateLoadingStatus(status);
        }
    },
    
    /**
     * Liste tous les dossiers dans cves/2025/
     */
    async listDirectories() {
        try {
            // Pour charger les fichiers, on doit connaître la structure
            // On va essayer de charger depuis les dossiers connus
            // Les dossiers sont organisés par milliers: 0xxx, 1xxx, 2xxx, etc.
            const directories = [];
            
            // On va essayer de détecter les dossiers en essayant de charger un fichier de test
            // Pour l'instant, on va utiliser une approche où on essaie les dossiers courants
            // L'utilisateur devra peut-être fournir une liste ou on peut utiliser une API
            
            // Approche alternative: utiliser fetch pour obtenir la liste
            // Mais comme on est en local, on va devoir scanner les dossiers connus
            
            // Liste des dossiers possibles (0xxx à 99xxx)
            for (let i = 0; i < 100; i++) {
                const dirName = i === 0 ? '0xxx' : `${i}xxx`;
                directories.push(dirName);
            }
            
            return directories;
        } catch (error) {
            console.error('Erreur lors de la liste des dossiers:', error);
            return [];
        }
    },
    
    /**
     * Charge tous les fichiers JSON d'un dossier
     */
    async loadFilesFromDirectory(directory) {
        try {
            // On va essayer de charger un fichier index ou lister les fichiers
            // Pour l'instant, on va utiliser une approche où on essaie de charger
            // les fichiers CVE directement
            
            // Note: Cette approche nécessite que le serveur HTTP serve les fichiers
            // On va essayer de charger les fichiers CVE-2025-XXXX.json
            
            // Pour optimiser, on pourrait créer un endpoint qui liste les fichiers
            // Mais pour l'instant, on va essayer une approche différente:
            // Charger les fichiers par leur ID connu
            
            // Approche: on va essayer de charger les fichiers dans une plage
            // Mais cela peut être très lent. Une meilleure approche serait d'avoir
            // un fichier index.json qui liste tous les CVE
            
            // Pour l'instant, on va retourner un tableau vide et laisser
            // l'application charger les fichiers à la demande
            
            return [];
        } catch (error) {
            console.error(`Erreur lors du chargement du dossier ${directory}:`, error);
            return [];
        }
    },
    
    /**
     * Vérifie si l'API SQLite est disponible
     */
    async checkSQLiteAPI() {
        try {
            const response = await fetch('/api/cves/count');
            return response.ok;
        } catch (error) {
            return false;
        }
    },
    
    /**
     * Charge un fichier CVE spécifique
     * Utilise l'API SQLite si disponible, sinon fallback sur fichiers/IndexedDB
     */
    async loadCVEFile(cveId, forceReload = false) {
        // Vérifier le cache mémoire d'abord
        if (this.cveCache.has(cveId) && !forceReload) {
            return this.cveCache.get(cveId);
        }
        
        // Vérifier IndexedDB si disponible et pas de rechargement forcé
        if (!forceReload && window.DB && window.DB.db) {
            try {
                const cveFromDB = await DB.getCVE(cveId);
                if (cveFromDB) {
                    // Mettre en cache mémoire
                    this.cveCache.set(cveId, cveFromDB);
                    return cveFromDB;
                }
            } catch (error) {
                console.warn(`Erreur lors de la lecture depuis IndexedDB pour ${cveId}:`, error);
            }
        }
        
        // Essayer d'abord l'API SQLite
        const sqliteAvailable = await this.checkSQLiteAPI();
        if (sqliteAvailable) {
            try {
                const response = await fetch(`/api/cves/${cveId}`);
                if (response.ok) {
                    const cveData = await response.json();
                    // Mettre en cache mémoire
                    this.cveCache.set(cveId, cveData);
                    // Stocker dans IndexedDB si disponible (cache secondaire)
                    if (window.DB && window.DB.db) {
                        try {
                            await DB.saveCVE(cveData);
                        } catch (error) {
                            console.warn(`Erreur lors du stockage dans IndexedDB pour ${cveId}:`, error);
                        }
                    }
                    return cveData;
                } else if (response.status === 404) {
                    return null;
                }
            } catch (error) {
                console.warn(`Erreur lors du chargement depuis l'API SQLite pour ${cveId}:`, error);
                // Fallback sur l'ancien système
            }
        }
        
        // Fallback: Charger depuis les fichiers
        try {
            // Extraire le numéro du CVE (ex: CVE-2025-0001 -> 0001)
            const match = cveId.match(/CVE-2025-(\d+)/);
            if (!match) {
                throw new Error(`Format CVE invalide: ${cveId}`);
            }
            
            const cveNumber = parseInt(match[1]);
            
            // Déterminer le dossier (ex: 0xxx pour 0-999, 1xxx pour 1000-1999, etc.)
            const folderNumber = Math.floor(cveNumber / 1000);
            const folderName = folderNumber === 0 ? '0xxx' : `${folderNumber}xxx`;
            
            // Construire le chemin
            const path = `${this.basePath}/${folderName}/${cveId}.json`;
            
            // Charger le fichier
            const response = await fetch(path);
            if (!response.ok) {
                // Si 404, le CVE n'existe pas encore
                if (response.status === 404) {
                    return null;
                }
                throw new Error(`Erreur HTTP ${response.status} pour ${path}`);
            }
            
            const cveData = await response.json();
            
            // Mettre en cache mémoire
            this.cveCache.set(cveId, cveData);
            
            // Stocker dans IndexedDB si disponible
            if (window.DB && window.DB.db) {
                try {
                    await DB.saveCVE(cveData);
                } catch (error) {
                    console.warn(`Erreur lors du stockage dans IndexedDB pour ${cveId}:`, error);
                }
            }
            
            return cveData;
        } catch (error) {
            console.error(`Erreur lors du chargement de ${cveId}:`, error);
            return null;
        }
    },
    
    /**
     * Charge tous les CVE en parcourant les dossiers
     * Cette méthode peut être lente, donc on va utiliser une approche progressive
     */
    async loadAllCVEs(progressCallback) {
        if (this.loading) {
            return this.cveIndex;
        }
        
        this.loading = true;
        this.cveIndex = [];
        
        try {
            // On va essayer de charger un fichier qui liste tous les CVE
            // Sinon, on va devoir scanner les dossiers
            
            // Approche: charger le fichier deltaLog.json qui pourrait contenir une liste
            try {
                const deltaLogResponse = await fetch(`${this.basePath}/deltaLog.json`);
                if (deltaLogResponse.ok) {
                    // Le fichier deltaLog.json pourrait être trop gros
                    // On va plutôt essayer une autre approche
                }
            } catch (e) {
                // Ignorer si le fichier n'existe pas
            }
            
            // Approche alternative: scanner les dossiers et charger les fichiers
            // Mais cela peut être très lent. On va plutôt charger les fichiers à la demande
            
            // Pour l'instant, on va retourner un index vide
            // L'application devra charger les fichiers individuellement
            
            this.loading = false;
            return this.cveIndex;
            
        } catch (error) {
            console.error('Erreur lors du chargement des CVE:', error);
            this.loading = false;
            return [];
        }
    },
    
    /**
     * Charge les CVE depuis une liste d'IDs
     */
    async loadCVEsFromList(cveIds, progressCallback) {
        const cves = [];
        const total = cveIds.length;
        
        for (let i = 0; i < total; i++) {
            const cveId = cveIds[i];
            const cve = await this.loadCVEFile(cveId);
            if (cve) {
                cves.push(cve);
                this.cveIndex.push(cve);
            }
            
            if (progressCallback) {
                progressCallback(i + 1, total, cveId);
            }
        }
        
        return cves;
    },
    
    /**
     * Extrait la liste des CVE disponibles depuis deltaLog.json
     */
    async getCVEListFromDeltaLog() {
        try {
            // deltaLog.json est à la racine du dossier cves/, pas dans cves/2025/
            const response = await fetch('cves/deltaLog.json');
            if (!response.ok) {
                throw new Error(`Erreur HTTP ${response.status} pour deltaLog.json`);
            }
            
            const deltaLog = await response.json();
            const cveIdsSet = new Set();
            
            // Parcourir tous les entrées du deltaLog
            for (const entry of deltaLog) {
                // Extraire les CVE des nouveaux (uniquement ceux de 2025)
                if (entry.new && Array.isArray(entry.new)) {
                    entry.new.forEach(item => {
                        if (item.cveId && item.cveId.startsWith('CVE-2025-')) {
                            cveIdsSet.add(item.cveId);
                        }
                    });
                }
                
                // Extraire les CVE des mises à jour (uniquement ceux de 2025)
                if (entry.updated && Array.isArray(entry.updated)) {
                    entry.updated.forEach(item => {
                        if (item.cveId && item.cveId.startsWith('CVE-2025-')) {
                            cveIdsSet.add(item.cveId);
                        }
                    });
                }
            }
            
            // Convertir en tableau trié
            const cveIds = Array.from(cveIdsSet).sort((a, b) => {
                // Extraire les numéros pour trier correctement
                const numA = parseInt(a.match(/CVE-2025-(\d+)/)?.[1] || '0');
                const numB = parseInt(b.match(/CVE-2025-(\d+)/)?.[1] || '0');
                return numA - numB;
            });
            
            console.log(`${cveIds.length} CVE uniques trouvés dans deltaLog.json`);
            return cveIds;
        } catch (error) {
            console.error('Erreur lors du chargement de deltaLog.json:', error);
            return [];
        }
    },
    
    /**
     * Charge l'index des CVE depuis index.json
     */
    async loadCVEIndex() {
        try {
            const response = await fetch(`${this.basePath}/index.json`);
            if (!response.ok) {
                throw new Error(`Erreur HTTP ${response.status} pour index.json`);
            }
            
            const index = await response.json();
            console.log(`Index chargé: ${index.totalCves} CVE disponibles`);
            return index;
        } catch (error) {
            console.warn('Impossible de charger index.json:', error);
            return null;
        }
    },
    
    /**
     * Charge plusieurs CVE en parallèle par lots avec taille adaptative
     * Utilise l'API SQLite /api/cves/batch si disponible pour de meilleures performances
     * @param {string[]} cveIds - Liste des IDs CVE à charger
     * @param {Function} progressCallback - Callback appelé avec (current, total, status)
     * @param {boolean} forceReload - Forcer le rechargement même si en cache
     * @param {Object} context - Contexte pour mettre à jour discovered, allCveIds, etc.
     * @returns {Promise<Array>} Liste des CVE chargées
     */
    async loadCVEsInParallel(cveIds, progressCallback, forceReload, context) {
        const { discovered, allCveIds, newCVEs } = context;
        
        // Vérifier si l'API SQLite est disponible
        const sqliteAvailable = await this.checkSQLiteAPI();
        
        if (sqliteAvailable && cveIds.length > 50) {
            // Utiliser l'API SQLite batch pour de meilleures performances
            return await this.loadCVEsFromSQLiteBatch(cveIds, progressCallback, forceReload, context);
        }
        
        // Fallback: chargement individuel (ancien système)
        let batchSize = 50; // Taille initiale du lot
        const minBatchSize = 10;
        const maxBatchSize = 100;
        let consecutiveFastBatches = 0;
        let consecutiveSlowBatches = 0;
        
        for (let i = 0; i < cveIds.length; i += batchSize) {
            const batch = cveIds.slice(i, Math.min(i + batchSize, cveIds.length));
            const batchStartTime = Date.now();
            
            // Charger le lot en parallèle
            const batchPromises = batch.map(cveId => 
                this.loadCVEFile(cveId, forceReload).catch(error => {
                    console.warn(`Erreur lors du chargement de ${cveId}:`, error);
                    return null;
                })
            );
            
            const batchResults = await Promise.allSettled(batchPromises);
            const batchDuration = Date.now() - batchStartTime;
            
            // Traiter les résultats du lot
            let batchLoaded = 0;
            for (let j = 0; j < batchResults.length; j++) {
                const result = batchResults[j];
                if (result.status === 'fulfilled' && result.value) {
                    const cve = result.value;
                    const cveId = cve.cveMetadata?.cveId;
                    
                    if (cveId && !allCveIds.has(cveId)) {
                        allCveIds.add(cveId);
                        newCVEs.push(cve);
                        discovered.push(cve);
                        context.cveIndex.push(cve);
                        batchLoaded++;
                    }
                }
            }
            
            // Ajuster la taille du lot selon les performances
            const avgTimePerCVE = batchDuration / batch.length;
            if (avgTimePerCVE < 50) {
                // Chargement rapide, augmenter la taille du lot
                consecutiveFastBatches++;
                consecutiveSlowBatches = 0;
                if (consecutiveFastBatches >= 3 && batchSize < maxBatchSize) {
                    batchSize = Math.min(batchSize + 10, maxBatchSize);
                    console.log(`Taille de lot augmentée à ${batchSize}`);
                }
            } else if (avgTimePerCVE > 200) {
                // Chargement lent, diminuer la taille du lot
                consecutiveSlowBatches++;
                consecutiveFastBatches = 0;
                if (consecutiveSlowBatches >= 2 && batchSize > minBatchSize) {
                    batchSize = Math.max(batchSize - 10, minBatchSize);
                    console.log(`Taille de lot diminuée à ${batchSize}`);
                }
            } else {
                // Performance normale, réinitialiser les compteurs
                consecutiveFastBatches = 0;
                consecutiveSlowBatches = 0;
            }
            
            // Stocker dans IndexedDB par lots de 100-200
            if (newCVEs.length >= 100 && window.DB && window.DB.db) {
                try {
                    const batchToSave = newCVEs.splice(0, 100);
                    await DB.saveCVEs(batchToSave);
                    console.log(`${batchToSave.length} CVE stockés dans IndexedDB (lot)`);
                } catch (error) {
                    console.warn('Erreur lors du stockage en lot dans IndexedDB:', error);
                }
            }
            
            // Mettre à jour le callback de progression
            if (progressCallback) {
                const totalExpected = context.cvesFromDB.length + cveIds.length;
                const currentLoaded = discovered.length;
                const lastCveId = batch[batch.length - 1];
                progressCallback(
                    currentLoaded,
                    totalExpected,
                    `Chargement: ${currentLoaded}/${totalExpected} (${lastCveId}) - Lot ${Math.floor(i / batchSize) + 1}`
                );
            }
            
            // Petite pause pour ne pas bloquer l'UI
            if (i % (batchSize * 5) === 0 && i > 0) {
                await new Promise(resolve => setTimeout(resolve, 10));
            }
        }
        
        // Stocker les CVE restantes dans IndexedDB
        if (newCVEs.length > 0 && window.DB && window.DB.db) {
            try {
                await DB.saveCVEs(newCVEs);
                console.log(`${newCVEs.length} CVE restants stockés dans IndexedDB`);
            } catch (error) {
                console.warn('Erreur lors du stockage final dans IndexedDB:', error);
            }
        }
        
        return discovered;
    },
    
    /**
     * Charge plusieurs CVE depuis l'API SQLite batch
     * Utilise /api/cves/batch avec lots de 500-1000 pour optimiser les performances
     */
    async loadCVEsFromSQLiteBatch(cveIds, progressCallback, forceReload, context) {
        const { discovered, allCveIds, newCVEs } = context;
        const batchSize = 1000; // Lots de 1000 CVE par requête
        
        for (let i = 0; i < cveIds.length; i += batchSize) {
            const batch = cveIds.slice(i, Math.min(i + batchSize, cveIds.length));
            
            try {
                // Appeler l'API batch avec les IDs séparés par des virgules
                const idsParam = batch.join(',');
                const response = await fetch(`/api/cves/batch?ids=${encodeURIComponent(idsParam)}`);
                
                if (!response.ok) {
                    throw new Error(`Erreur HTTP ${response.status} pour /api/cves/batch`);
                }
                
                const data = await response.json();
                const cves = data.cves || [];
                
                // Traiter les CVE chargées
                for (const cve of cves) {
                    const cveId = cve.cveMetadata?.cveId;
                    if (cveId && !allCveIds.has(cveId)) {
                        allCveIds.add(cveId);
                        newCVEs.push(cve);
                        discovered.push(cve);
                        context.cveIndex.push(cve);
                        // Mettre en cache mémoire
                        this.cveCache.set(cveId, cve);
                    }
                }
                
                // Stocker dans IndexedDB par lots de 200
                if (newCVEs.length >= 200 && window.DB && window.DB.db) {
                    try {
                        const batchToSave = newCVEs.splice(0, 200);
                        await DB.saveCVEs(batchToSave);
                    } catch (error) {
                        console.warn('Erreur lors du stockage en lot dans IndexedDB:', error);
                    }
                }
                
                // Mettre à jour le callback de progression
                if (progressCallback) {
                    const totalExpected = context.cvesFromDB.length + cveIds.length;
                    const currentLoaded = discovered.length;
                    const lastCveId = batch[batch.length - 1];
                    progressCallback(
                        currentLoaded,
                        totalExpected,
                        `Chargement SQLite: ${currentLoaded}/${totalExpected} (${lastCveId}) - Lot ${Math.floor(i / batchSize) + 1}`
                    );
                }
                
                // Petite pause pour ne pas bloquer l'UI
                await new Promise(resolve => setTimeout(resolve, 10));
                
            } catch (error) {
                console.error(`Erreur lors du chargement du lot ${i}-${i + batch.length}:`, error);
                // En cas d'erreur, charger individuellement les CVE du lot
                for (const cveId of batch) {
                    const cve = await this.loadCVEFile(cveId, forceReload);
                    if (cve) {
                        const id = cve.cveMetadata?.cveId;
                        if (id && !allCveIds.has(id)) {
                            allCveIds.add(id);
                            newCVEs.push(cve);
                            discovered.push(cve);
                            context.cveIndex.push(cve);
                        }
                    }
                }
            }
        }
        
        // Stocker les CVE restantes dans IndexedDB
        if (newCVEs.length > 0 && window.DB && window.DB.db) {
            try {
                await DB.saveCVEs(newCVEs);
                console.log(`${newCVEs.length} CVE restants stockés dans IndexedDB`);
            } catch (error) {
                console.warn('Erreur lors du stockage final dans IndexedDB:', error);
            }
        }
        
        return discovered;
    },
    
    /**
     * Liste les dossiers disponibles dans cves/2025/
     */
    async listAvailableDirectories() {
        const directories = [];
        // Liste des dossiers possibles basée sur la structure réelle
        // On essaie les dossiers de 0xxx à 99xxx
        for (let i = 0; i < 100; i++) {
            const dirName = i === 0 ? '0xxx' : `${i}xxx`;
            directories.push(dirName);
        }
        // Ajouter aussi les dossiers avec 5 chiffres (ex: 10xxx, 11xxx, etc.)
        for (let i = 10; i < 100; i++) {
            directories.push(`${i}xxx`);
        }
        return directories;
    },
    
    /**
     * Découvre les fichiers CVE en parcourant les dossiers de cves/2025/
     * Utilise l'API SQLite si disponible pour de meilleures performances
     * Sinon utilise IndexedDB et les fichiers
     */
    async discoverCVEsFromDirectories(progressCallback, forceReload = false) {
        const discovered = [];
        const allCveIds = new Set();
        
        // Vérifier si l'API SQLite est disponible
        const sqliteAvailable = await this.checkSQLiteAPI();
        
        if (sqliteAvailable) {
            // Utiliser l'API SQLite pour charger tous les CVE par pagination
            return await this.loadCVEsFromSQLite(progressCallback, forceReload);
        }
        
        // Fallback: ancien système avec IndexedDB et fichiers
        // Si IndexedDB contient déjà des CVE et pas de rechargement forcé, les charger d'abord
        let cvesFromDB = [];
        let storedIds = new Set();
        
        if (!forceReload && window.DB && window.DB.db) {
            try {
                cvesFromDB = await DB.getAllCVEs();
                cvesFromDB.forEach(cve => {
                    const id = cve.cveMetadata?.cveId;
                    if (id && id.startsWith('CVE-2025-')) {
                        allCveIds.add(id);
                        storedIds.add(id);
                        this.cveCache.set(id, cve);
                        if (!this.cveIndex.find(c => c.cveMetadata?.cveId === id)) {
                            this.cveIndex.push(cve);
                        }
                    }
                });
                discovered.push(...cvesFromDB);
                console.log(`${cvesFromDB.length} CVE chargées depuis IndexedDB`);
                if (progressCallback && cvesFromDB.length > 0) {
                    progressCallback(cvesFromDB.length, 0, `Chargés depuis IndexedDB: ${cvesFromDB.length}`);
                }
            } catch (error) {
                console.warn('Erreur lors de la lecture depuis IndexedDB:', error);
            }
        }
        
        // Essayer de charger l'index des CVE (généré par generate-cve-index.js)
        this.updateLoadingStatus('Chargement de l\'index des CVE...');
        const cveIndex = await this.loadCVEIndex();
        
        if (cveIndex && cveIndex.cveIds && cveIndex.cveIds.length > 0) {
            // Utiliser l'index pour charger uniquement les CVE qui existent vraiment
            this.updateLoadingStatus(`Chargement de ${cveIndex.totalCves} CVE depuis l'index...`);
            const missingIds = cveIndex.cveIds.filter(id => !storedIds.has(id));
            const newCVEs = [];
            
            // Charger en parallèle par lots avec taille adaptative
            await this.loadCVEsInParallel(
                missingIds,
                progressCallback,
                forceReload,
                {
                    discovered,
                    allCveIds,
                    newCVEs,
                    cveIndex: this.cveIndex,
                    cvesFromDB
                }
            );
            
            console.log(`Total: ${discovered.length} CVE (${cvesFromDB.length} depuis IndexedDB, ${newCVEs.length} nouvelles depuis l'index)`);
            return discovered;
        }
        
        // Fallback: utiliser deltaLog.json si l'index n'existe pas
        this.updateLoadingStatus('Chargement de la liste des CVE depuis deltaLog.json...');
        const cveIdsFromDeltaLog = await this.getCVEListFromDeltaLog();
        const knownCveIds = new Set(cveIdsFromDeltaLog);
        
        if (knownCveIds.size > 0) {
            this.updateLoadingStatus(`Chargement de ${knownCveIds.size} CVE depuis deltaLog.json...`);
            const missingIds = Array.from(knownCveIds).filter(id => !storedIds.has(id));
            const newCVEs = [];
            
            // Charger en parallèle par lots avec taille adaptative
            await this.loadCVEsInParallel(
                missingIds,
                progressCallback,
                forceReload,
                {
                    discovered,
                    allCveIds,
                    newCVEs,
                    cveIndex: this.cveIndex,
                    cvesFromDB
                }
            );
            
            console.log(`Total: ${discovered.length} CVE (${cvesFromDB.length} depuis IndexedDB, ${newCVEs.length} nouvelles)`);
            return discovered;
        }
        
        // Dernier recours: retourner ce qui a été chargé depuis IndexedDB
        console.warn('Index et deltaLog.json non disponibles');
        console.log(`Retour de ${discovered.length} CVE depuis IndexedDB uniquement`);
        return discovered;
    },
    
    /**
     * Charge tous les CVE depuis l'API SQLite avec pagination
     * Beaucoup plus rapide que le chargement individuel
     */
    async loadCVEsFromSQLite(progressCallback, forceReload) {
        const discovered = [];
        const allCveIds = new Set();
        const newCVEs = [];
        
        try {
            // Obtenir le nombre total de CVE
            const countResponse = await fetch('/api/cves/count');
            if (!countResponse.ok) {
                throw new Error('Impossible de récupérer le nombre de CVE');
            }
            const countData = await countResponse.json();
            const totalCves = countData.count;
            
            this.updateLoadingStatus(`Chargement de ${totalCves} CVE depuis SQLite...`);
            
            // Charger par pages de 2000 CVE
            const pageSize = 2000;
            const totalPages = Math.ceil(totalCves / pageSize);
            
            for (let page = 1; page <= totalPages; page++) {
                const response = await fetch(`/api/cves?page=${page}&limit=${pageSize}&sort=dateDesc`);
                
                if (!response.ok) {
                    throw new Error(`Erreur HTTP ${response.status} pour /api/cves`);
                }
                
                const data = await response.json();
                const cves = data.cves || [];
                
                // Traiter les CVE chargées
                for (const cve of cves) {
                    const cveId = cve.cveMetadata?.cveId;
                    if (cveId && !allCveIds.has(cveId)) {
                        allCveIds.add(cveId);
                        newCVEs.push(cve);
                        discovered.push(cve);
                        this.cveIndex.push(cve);
                        // Mettre en cache mémoire
                        this.cveCache.set(cveId, cve);
                    }
                }
                
                // Stocker dans IndexedDB par lots de 200
                if (newCVEs.length >= 200 && window.DB && window.DB.db) {
                    try {
                        const batchToSave = newCVEs.splice(0, 200);
                        await DB.saveCVEs(batchToSave);
                    } catch (error) {
                        console.warn('Erreur lors du stockage en lot dans IndexedDB:', error);
                    }
                }
                
                // Mettre à jour le callback de progression
                if (progressCallback) {
                    progressCallback(
                        discovered.length,
                        totalCves,
                        `Chargement SQLite: ${discovered.length}/${totalCves} - Page ${page}/${totalPages}`
                    );
                }
                
                // Petite pause pour ne pas bloquer l'UI
                await new Promise(resolve => setTimeout(resolve, 10));
            }
            
            // Stocker les CVE restantes dans IndexedDB
            if (newCVEs.length > 0 && window.DB && window.DB.db) {
                try {
                    await DB.saveCVEs(newCVEs);
                    console.log(`${newCVEs.length} CVE restants stockés dans IndexedDB`);
                } catch (error) {
                    console.warn('Erreur lors du stockage final dans IndexedDB:', error);
                }
            }
            
            console.log(`Total: ${discovered.length} CVE chargées depuis SQLite`);
            return discovered;
            
        } catch (error) {
            console.error('Erreur lors du chargement depuis SQLite:', error);
            // Retourner ce qui a été chargé jusqu'à présent
            return discovered;
        }
    },
    
    /**
     * Découvre les fichiers CVE disponibles en scannant les dossiers
     * Cette méthode essaie de charger les fichiers dans une plage donnée
     * Utilise IndexedDB pour éviter de recharger les CVE déjà stockés
     * @deprecated Utiliser discoverCVEsFromDeltaLog() à la place
     */
    async discoverCVEsInRange(startId, endId, progressCallback, forceReload = false) {
        const cveIds = [];
        const discovered = [];
        
        // Générer la liste des IDs CVE dans la plage
        for (let i = startId; i <= endId; i++) {
            const cveId = `CVE-2025-${String(i).padStart(4, '0')}`;
            cveIds.push(cveId);
        }
        
        // Si IndexedDB est disponible et pas de rechargement forcé, vérifier quels CVE sont déjà stockés
        let cvesFromDB = [];
        let missingIds = cveIds;
        
        if (!forceReload && window.DB && window.DB.db) {
            try {
                // Charger tous les CVE depuis IndexedDB
                const allStoredCVEs = await DB.getAllCVEs();
                const storedIds = new Set(allStoredCVEs.map(cve => cve.cveMetadata?.cveId));
                
                // Séparer les CVE déjà stockés et ceux manquants
                cvesFromDB = allStoredCVEs.filter(cve => {
                    const id = cve.cveMetadata?.cveId;
                    return id && cveIds.includes(id);
                });
                
                missingIds = cveIds.filter(id => !storedIds.has(id));
                
                // Ajouter les CVE depuis IndexedDB au cache mémoire et à l'index
                cvesFromDB.forEach(cve => {
                    const id = cve.cveMetadata?.cveId;
                    if (id) {
                        this.cveCache.set(id, cve);
                        if (!this.cveIndex.find(c => c.cveMetadata?.cveId === id)) {
                            this.cveIndex.push(cve);
                        }
                    }
                });
                
                discovered.push(...cvesFromDB);
                
                if (progressCallback && cvesFromDB.length > 0) {
                    progressCallback(cvesFromDB.length, cveIds.length, `Chargés depuis IndexedDB: ${cvesFromDB.length}`);
                }
            } catch (error) {
                console.warn('Erreur lors de la lecture depuis IndexedDB:', error);
                missingIds = cveIds; // En cas d'erreur, tout charger
            }
        }
        
        // Charger uniquement les CVE manquants depuis les fichiers
        const newCVEs = [];
        for (let i = 0; i < missingIds.length; i++) {
            const cveId = missingIds[i];
            const cve = await this.loadCVEFile(cveId, forceReload);
            
            if (cve) {
                newCVEs.push(cve);
                discovered.push(cve);
                this.cveIndex.push(cve);
            }
            
            if (progressCallback && (i % 10 === 0 || i === missingIds.length - 1)) {
                const totalProcessed = cvesFromDB.length + i + 1;
                progressCallback(totalProcessed, cveIds.length, cveId);
            }
            
            // Petite pause pour ne pas surcharger
            if (i % 50 === 0 && i > 0) {
                await new Promise(resolve => setTimeout(resolve, 10));
            }
        }
        
        // Stocker les nouveaux CVE dans IndexedDB par lot
        if (newCVEs.length > 0 && window.DB && window.DB.db) {
            try {
                await DB.saveCVEs(newCVEs);
                console.log(`${newCVEs.length} nouveaux CVE stockés dans IndexedDB`);
            } catch (error) {
                console.warn('Erreur lors du stockage en lot dans IndexedDB:', error);
            }
        }
        
        return discovered;
    },
    
    /**
     * Obtient l'index des CVE chargés
     */
    getIndex() {
        return this.cveIndex;
    },
    
    /**
     * Réinitialise le chargeur
     */
    reset() {
        this.cveIndex = [];
        this.cveCache.clear();
        this.loading = false;
    }
};

