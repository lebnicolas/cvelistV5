/**
 * Gestion de la base de données IndexedDB pour le cache des CVE
 */

const DB = {
    dbName: 'CVE2025DB',
    dbVersion: 1,
    storeName: 'cves',
    db: null,
    
    /**
     * Ouvre la base de données IndexedDB
     */
    async open() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.dbVersion);
            
            request.onerror = () => {
                console.error('Erreur lors de l\'ouverture de la base de données:', request.error);
                reject(request.error);
            };
            
            request.onsuccess = () => {
                this.db = request.result;
                console.log('Base de données IndexedDB ouverte');
                resolve(this.db);
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Créer le store s'il n'existe pas
                if (!db.objectStoreNames.contains(this.storeName)) {
                    const objectStore = db.createObjectStore(this.storeName, { keyPath: 'cveId' });
                    
                    // Créer des index pour la recherche rapide
                    objectStore.createIndex('cveId', 'cveId', { unique: true });
                    objectStore.createIndex('datePublished', 'datePublished', { unique: false });
                    objectStore.createIndex('state', 'state', { unique: false });
                    
                    console.log('Store et index créés dans IndexedDB');
                }
            };
        });
    },
    
    /**
     * Vérifie si la base de données est ouverte
     */
    ensureOpen() {
        if (!this.db) {
            throw new Error('La base de données n\'est pas ouverte. Appelez DB.open() d\'abord.');
        }
    },
    
    /**
     * Stocke un CVE dans IndexedDB
     */
    async saveCVE(cve) {
        this.ensureOpen();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([this.storeName], 'readwrite');
            const store = transaction.objectStore(this.storeName);
            
            // Préparer les données avec l'ID CVE comme clé
            const cveData = {
                cveId: cve.cveMetadata?.cveId,
                datePublished: cve.cveMetadata?.datePublished,
                state: cve.cveMetadata?.state,
                data: cve, // Stocker l'objet CVE complet
                lastUpdated: new Date().toISOString()
            };
            
            const request = store.put(cveData);
            
            request.onsuccess = () => {
                resolve();
            };
            
            request.onerror = () => {
                console.error('Erreur lors du stockage du CVE:', request.error);
                reject(request.error);
            };
        });
    },
    
    /**
     * Stocke plusieurs CVE dans IndexedDB
     */
    async saveCVEs(cves) {
        this.ensureOpen();
        
        const transaction = this.db.transaction([this.storeName], 'readwrite');
        const store = transaction.objectStore(this.storeName);
        
        return new Promise((resolve, reject) => {
            let completed = 0;
            let errors = 0;
            const total = cves.length;
            
            if (total === 0) {
                resolve({ saved: 0, errors: 0 });
                return;
            }
            
            cves.forEach((cve) => {
                const cveData = {
                    cveId: cve.cveMetadata?.cveId,
                    datePublished: cve.cveMetadata?.datePublished,
                    state: cve.cveMetadata?.state,
                    data: cve,
                    lastUpdated: new Date().toISOString()
                };
                
                const request = store.put(cveData);
                
                request.onsuccess = () => {
                    completed++;
                    if (completed + errors === total) {
                        resolve({ saved: completed, errors: errors });
                    }
                };
                
                request.onerror = () => {
                    errors++;
                    console.error(`Erreur lors du stockage de ${cveData.cveId}:`, request.error);
                    if (completed + errors === total) {
                        resolve({ saved: completed, errors: errors });
                    }
                };
            });
        });
    },
    
    /**
     * Récupère un CVE par son ID
     */
    async getCVE(cveId) {
        this.ensureOpen();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([this.storeName], 'readonly');
            const store = transaction.objectStore(this.storeName);
            const request = store.get(cveId);
            
            request.onsuccess = () => {
                if (request.result) {
                    resolve(request.result.data); // Retourner l'objet CVE complet
                } else {
                    resolve(null);
                }
            };
            
            request.onerror = () => {
                console.error('Erreur lors de la récupération du CVE:', request.error);
                reject(request.error);
            };
        });
    },
    
    /**
     * Récupère tous les CVE depuis IndexedDB
     */
    async getAllCVEs() {
        this.ensureOpen();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([this.storeName], 'readonly');
            const store = transaction.objectStore(this.storeName);
            const request = store.getAll();
            
            request.onsuccess = () => {
                // Extraire les objets CVE depuis les données stockées
                const cves = request.result.map(item => item.data);
                console.log(`${cves.length} CVE chargés depuis IndexedDB`);
                resolve(cves);
            };
            
            request.onerror = () => {
                console.error('Erreur lors de la récupération des CVE:', request.error);
                reject(request.error);
            };
        });
    },
    
    /**
     * Vérifie si un CVE existe dans la base de données
     */
    async hasCVE(cveId) {
        this.ensureOpen();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([this.storeName], 'readonly');
            const store = transaction.objectStore(this.storeName);
            const request = store.count(IDBKeyRange.only(cveId));
            
            request.onsuccess = () => {
                resolve(request.result > 0);
            };
            
            request.onerror = () => {
                reject(request.error);
            };
        });
    },
    
    /**
     * Compte le nombre total de CVE dans la base de données
     */
    async countCVEs() {
        this.ensureOpen();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([this.storeName], 'readonly');
            const store = transaction.objectStore(this.storeName);
            const request = store.count();
            
            request.onsuccess = () => {
                resolve(request.result);
            };
            
            request.onerror = () => {
                reject(request.error);
            };
        });
    },
    
    /**
     * Vide complètement la base de données
     */
    async clearAll() {
        this.ensureOpen();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([this.storeName], 'readwrite');
            const store = transaction.objectStore(this.storeName);
            const request = store.clear();
            
            request.onsuccess = () => {
                console.log('Base de données IndexedDB vidée');
                resolve();
            };
            
            request.onerror = () => {
                console.error('Erreur lors du vidage de la base de données:', request.error);
                reject(request.error);
            };
        });
    },
    
    /**
     * Récupère les IDs de tous les CVE stockés
     */
    async getAllCVEIds() {
        this.ensureOpen();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([this.storeName], 'readonly');
            const store = transaction.objectStore(this.storeName);
            const request = store.getAllKeys();
            
            request.onsuccess = () => {
                resolve(request.result);
            };
            
            request.onerror = () => {
                reject(request.error);
            };
        });
    },
    
    /**
     * Vérifie quels CVE manquent dans la base de données
     */
    async getMissingCVEIds(cveIds) {
        this.ensureOpen();
        
        const storedIds = await this.getAllCVEIds();
        const storedSet = new Set(storedIds);
        
        return cveIds.filter(id => !storedSet.has(id));
    },
    
    /**
     * Ferme la base de données
     */
    close() {
        if (this.db) {
            this.db.close();
            this.db = null;
            console.log('Base de données IndexedDB fermée');
        }
    }
};

