/**
 * Application principale CVE
 * Orchestre le chargement, la recherche, le filtrage et l'affichage
 */

const APP = {
    allCVEs: [],
    filteredCVEs: [],
    currentFilters: {
        search: '',
        severity: '',
        state: '',
        cvssMin: '',
        cvssMax: ''
    },
    activeFilters: {
        search: [], // Tableau de termes de recherche
        severity: [],
        state: [],
        cvssMin: [],
        cvssMax: []
    },
    currentSort: 'dateDesc',
    isLoading: false,
    
    /**
     * Initialise l'application
     */
    async init() {
        console.log('Initialisation de l\'application CVE...');
        
        // Ouvrir IndexedDB
        try {
            await DB.open();
            window.DB = DB; // Exposer globalement pour cveLoader
            console.log('IndexedDB initialisée');
        } catch (error) {
            console.warn('Impossible d\'ouvrir IndexedDB:', error);
            // Continuer sans IndexedDB
        }
        
        // Attacher les event listeners
        this.attachEventListeners();
        
        // Démarrer le chargement des CVE
        await this.loadCVEs();
    },
    
    /**
     * Attache les event listeners
     */
    attachEventListeners() {
        // Recherche
        const searchInput = document.getElementById('searchInput');
        const searchBtn = document.getElementById('searchBtn');
        
        // Fonction pour appliquer la recherche (appelée sur Entrée ou clic bouton)
        const applySearch = () => {
            const searchValue = searchInput.value.trim();
            
            // Gérer les filtres actifs pour la recherche
            if (searchValue) {
                // Ajouter le nouveau filtre sans supprimer les existants (permet plusieurs filtres)
                this.addActiveFilter('search', searchValue, searchValue);
                // Vider le champ de recherche pour permettre d'ajouter un autre filtre
                searchInput.value = '';
            }
            // Note: Ne pas supprimer les filtres si la barre est vide, 
            // l'utilisateur peut les supprimer manuellement via les badges
        };
        
        // Filtrer uniquement sur Entrée ou clic bouton
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                applySearch();
            }
        });
        
        searchBtn.addEventListener('click', () => {
            applySearch();
        });
        
        // Filtres
        document.getElementById('severityFilter').addEventListener('change', (e) => {
            const value = e.target.value;
            this.currentFilters.severity = value;
            
            if (value) {
                const label = e.target.options[e.target.selectedIndex].text;
                this.activeFilters.severity = [];
                this.addActiveFilter('severity', value, label);
            } else {
                this.activeFilters.severity = [];
                this.renderActiveFilters();
            }
            
            this.applyFilters();
        });
        
        document.getElementById('stateFilter').addEventListener('change', (e) => {
            const value = e.target.value;
            this.currentFilters.state = value;
            
            if (value) {
                const label = e.target.options[e.target.selectedIndex].text;
                this.activeFilters.state = [];
                this.addActiveFilter('state', value, label);
            } else {
                this.activeFilters.state = [];
                this.renderActiveFilters();
            }
            
            this.applyFilters();
        });
        
        document.getElementById('cvssMinFilter').addEventListener('input', (e) => {
            const value = e.target.value;
            this.currentFilters.cvssMin = value;
            
            if (value) {
                this.activeFilters.cvssMin = [];
                this.addActiveFilter('cvssMin', value, `≥ ${value}`);
            } else {
                this.activeFilters.cvssMin = [];
                this.renderActiveFilters();
            }
            
            this.applyFilters();
        });
        
        document.getElementById('cvssMaxFilter').addEventListener('input', (e) => {
            const value = e.target.value;
            this.currentFilters.cvssMax = value;
            
            if (value) {
                this.activeFilters.cvssMax = [];
                this.addActiveFilter('cvssMax', value, `≤ ${value}`);
            } else {
                this.activeFilters.cvssMax = [];
                this.renderActiveFilters();
            }
            
            this.applyFilters();
        });
        
        document.getElementById('sortBy').addEventListener('change', (e) => {
            this.currentSort = e.target.value;
            this.applyFilters();
        });
        
        document.getElementById('clearFilters').addEventListener('click', () => {
            this.clearFilters();
        });
        
        // Bouton Actualiser
        const refreshBtn = document.getElementById('refreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.refreshCVEs();
            });
        }
        
        // Modal
        const modal = document.getElementById('cveModal');
        const closeBtn = document.getElementById('closeModal');
        
        closeBtn.addEventListener('click', () => {
            CVE_RENDERER.closeModal();
        });
        
        window.addEventListener('click', (e) => {
            if (e.target === modal) {
                CVE_RENDERER.closeModal();
            }
        });
        
        // Fermer avec Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && modal.style.display === 'block') {
                CVE_RENDERER.closeModal();
            }
        });
    },
    
    /**
     * Charge les CVE depuis IndexedDB ou les fichiers
     */
    async loadCVEs(forceReload = false) {
        this.isLoading = true;
        this.updateLoadingStatus('Chargement des CVE...');
        
        // Forcer la page à rester en haut au début du chargement
        window.scrollTo(0, 0);
        
        try {
            // Charger depuis les fichiers en parcourant les dossiers de cves/2025/
            this.updateLoadingStatus('Parcours des dossiers CVE...');
            
            let lastUpdateCount = 0;
            const UPDATE_INTERVAL = 100; // Mettre à jour l'affichage tous les 100 CVE
            
            const discovered = await CVE_LOADER.discoverCVEsFromDirectories(
                (current, total, status) => {
                    // Utiliser le message de statut s'il est fourni, sinon formater avec current/total
                    if (status) {
                        this.updateLoadingStatus(status);
                    } else {
                        this.updateLoadingStatus(`Chargement: ${current}${total ? `/${total}` : ''} CVE trouvées`);
                    }
                    
                    // Mettre à jour l'affichage progressivement
                    // Utiliser le tableau discovered qui est mis à jour pendant le chargement
                    if (current - lastUpdateCount >= UPDATE_INTERVAL || current === total) {
                        // Récupérer les CVE actuellement chargées depuis le loader
                        const currentCVEs = CVE_LOADER.cveIndex || [];
                        this.allCVEs = [...currentCVEs];
                        this.updateStats();
                        
                        // Forcer à rester en haut pendant le chargement
                        if (this.isLoading) {
                            requestAnimationFrame(() => {
                                window.scrollTo(0, 0);
                            });
                        }
                        
                        // Appliquer les filtres pour mettre à jour l'affichage
                        this.applyFilters();
                        
                        lastUpdateCount = current;
                    }
                },
                forceReload
            );
            
            // Récupérer toutes les CVE chargées
            this.allCVEs = discovered;
            this.updateStats();
            
            // Appliquer les filtres finaux
            this.applyFilters();
            
            this.updateLoadingStatus(`Chargement terminé: ${discovered.length} CVE`);
            
        } catch (error) {
            console.error('Erreur lors du chargement des CVE:', error);
            this.updateLoadingStatus('Erreur lors du chargement');
            document.getElementById('cveList').innerHTML = 
                '<div class="loading-message">Erreur lors du chargement des CVE. Vérifiez que vous utilisez un serveur HTTP local.</div>';
        } finally {
            this.isLoading = false;
        }
    },
    
    /**
     * Charge les nouveaux CVE en arrière-plan
     */
    async loadNewCVEs() {
        try {
            // Charger uniquement les nouveaux CVE en parcourant les dossiers
            const discovered = await CVE_LOADER.discoverCVEsFromDirectories(
                () => {}, // Pas de callback de progression en arrière-plan
                false // Ne pas forcer le rechargement
            );
            
            // Mettre à jour la liste si de nouveaux CVE ont été trouvés
            if (discovered.length > this.allCVEs.length) {
                this.allCVEs = discovered;
                this.updateStats();
                this.applyFilters();
                console.log(`${discovered.length - this.allCVEs.length} nouveaux CVE chargés`);
            }
        } catch (error) {
            console.warn('Erreur lors du chargement des nouveaux CVE:', error);
        }
    },
    
    /**
     * Force le rechargement complet depuis les fichiers
     */
    async refreshCVEs() {
        if (!confirm('Voulez-vous forcer le rechargement complet de tous les CVE depuis les fichiers ? Cela peut prendre du temps.')) {
            return;
        }
        
        this.updateLoadingStatus('Rechargement forcé...');
        await this.loadCVEs(true);
    },
    
    /**
     * Applique les filtres et la recherche
     */
    applyFilters() {
        let filtered = this.allCVEs;
        
        // Appliquer les filtres de recherche texte (peut y en avoir plusieurs)
        if (this.activeFilters.search.length > 0) {
            this.activeFilters.search.forEach(filter => {
                filtered = searchCVEs(filtered, filter.value);
            });
        } else if (this.currentFilters.search) {
            // Fallback pour compatibilité
            filtered = searchCVEs(filtered, this.currentFilters.search);
        }
        
        // Appliquer les filtres de sévérité
        if (this.activeFilters.severity.length > 0) {
            this.activeFilters.severity.forEach(filter => {
                filtered = filterCVEs(filtered, { severity: filter.value });
            });
        } else if (this.currentFilters.severity) {
            filtered = filterCVEs(filtered, { severity: this.currentFilters.severity });
        }
        
        // Appliquer les filtres d'état
        if (this.activeFilters.state.length > 0) {
            this.activeFilters.state.forEach(filter => {
                filtered = filterCVEs(filtered, { state: filter.value });
            });
        } else if (this.currentFilters.state) {
            filtered = filterCVEs(filtered, { state: this.currentFilters.state });
        }
        
        // Appliquer les filtres CVSS Min
        if (this.activeFilters.cvssMin.length > 0) {
            const maxCvssMin = Math.max(...this.activeFilters.cvssMin.map(f => parseFloat(f.value) || 0));
            filtered = filterCVEs(filtered, { cvssMin: maxCvssMin.toString() });
        } else if (this.currentFilters.cvssMin) {
            filtered = filterCVEs(filtered, { cvssMin: this.currentFilters.cvssMin });
        }
        
        // Appliquer les filtres CVSS Max
        if (this.activeFilters.cvssMax.length > 0) {
            const minCvssMax = Math.min(...this.activeFilters.cvssMax.map(f => parseFloat(f.value) || 10));
            filtered = filterCVEs(filtered, { cvssMax: minCvssMax.toString() });
        } else if (this.currentFilters.cvssMax) {
            filtered = filterCVEs(filtered, { cvssMax: this.currentFilters.cvssMax });
        }
        
        // Tri
        filtered = sortCVEs(filtered, this.currentSort);
        
        this.filteredCVEs = filtered;
        this.updateStats();
        
        // Afficher la première page
        this.goToPage(1);
    },
    
    /**
     * Efface tous les filtres
     */
    clearFilters() {
        document.getElementById('searchInput').value = '';
        document.getElementById('severityFilter').value = '';
        document.getElementById('stateFilter').value = '';
        document.getElementById('cvssMinFilter').value = '';
        document.getElementById('cvssMaxFilter').value = '';
        document.getElementById('sortBy').value = 'dateDesc';
        
        this.currentFilters = {
            search: '',
            severity: '',
            state: '',
            cvssMin: '',
            cvssMax: ''
        };
        this.currentSort = 'dateDesc';
        
        // Réinitialiser les filtres actifs
        this.activeFilters = {
            search: [],
            severity: [],
            state: [],
            cvssMin: [],
            cvssMax: []
        };
        this.renderActiveFilters();
        this.applyFilters();
    },
    
    /**
     * Obtient le label d'un type de filtre
     */
    getFilterTypeLabel(type) {
        const labels = {
            search: 'Recherche',
            severity: 'Sévérité',
            state: 'État',
            cvssMin: 'CVSS Min',
            cvssMax: 'CVSS Max'
        };
        return labels[type] || type;
    },
    
    /**
     * Ajoute un filtre actif
     */
    addActiveFilter(type, value, label) {
        if (!this.activeFilters[type]) {
            this.activeFilters[type] = [];
        }
        // Éviter les doublons
        if (!this.activeFilters[type].some(f => f.value === value)) {
            this.activeFilters[type].push({ value, label });
            this.renderActiveFilters();
            this.applyFilters();
        }
    },
    
    /**
     * Supprime un filtre actif
     */
    removeActiveFilter(type, value) {
        if (this.activeFilters[type]) {
            this.activeFilters[type] = this.activeFilters[type].filter(f => f.value !== value);
            
            // Mettre à jour les champs du formulaire si nécessaire
            if (type === 'search') {
                document.getElementById('searchInput').value = '';
            } else if (type === 'severity') {
                document.getElementById('severityFilter').value = '';
            } else if (type === 'state') {
                document.getElementById('stateFilter').value = '';
            } else if (type === 'cvssMin') {
                document.getElementById('cvssMinFilter').value = '';
            } else if (type === 'cvssMax') {
                document.getElementById('cvssMaxFilter').value = '';
            }
            
            this.renderActiveFilters();
            this.applyFilters();
        }
    },
    
    /**
     * Affiche les badges de filtres actifs
     */
    renderActiveFilters() {
        const container = document.getElementById('activeFilters');
        const badgesContainer = document.getElementById('filterBadges');
        
        if (!container || !badgesContainer) {
            return;
        }
        
        // Compter le nombre total de filtres actifs
        const totalFilters = Object.values(this.activeFilters).reduce((sum, filters) => sum + filters.length, 0);
        
        if (totalFilters === 0) {
            container.style.display = 'none';
            return;
        }
        
        container.style.display = 'block';
        badgesContainer.innerHTML = '';
        
        // Rendre chaque filtre actif
        Object.entries(this.activeFilters).forEach(([type, filters]) => {
            filters.forEach(filter => {
                const badge = document.createElement('span');
                badge.className = 'filter-badge';
                badge.innerHTML = `
                    <span class="filter-type">${this.getFilterTypeLabel(type)}:</span>
                    <span class="filter-value">${filter.label}</span>
                    <span class="remove-filter" data-type="${type}" data-value="${filter.value}">×</span>
                `;
                badgesContainer.appendChild(badge);
            });
        });
        
        // Ajouter les event listeners pour les boutons de suppression
        badgesContainer.querySelectorAll('.remove-filter').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const type = e.target.dataset.type;
                const value = e.target.dataset.value;
                this.removeActiveFilter(type, value);
            });
        });
    },
    
    /**
     * Va à une page spécifique
     */
    goToPage(page) {
        CVE_RENDERER.renderCVEList(this.filteredCVEs, page);
        
        // Rester en haut de la page sans animation pour éviter le décalage
        window.scrollTo(0, 0);
    },
    
    /**
     * Affiche les détails d'un CVE
     */
    async showCVEDetails(cveId) {
        // Chercher dans les CVE déjà chargés
        let cve = this.allCVEs.find(c => c.cveMetadata?.cveId === cveId);
        
        // Si pas trouvé, charger depuis le fichier
        if (!cve) {
            this.updateLoadingStatus(`Chargement de ${cveId}...`);
            cve = await CVE_LOADER.loadCVEFile(cveId);
            if (cve && !this.allCVEs.find(c => c.cveMetadata?.cveId === cveId)) {
                this.allCVEs.push(cve);
            }
        }
        
        if (cve) {
            CVE_RENDERER.renderCVEDetails(cve);
        } else {
            alert(`Impossible de charger les détails de ${cveId}`);
        }
    },
    
    /**
     * Met à jour les statistiques
     */
    updateStats() {
        document.getElementById('totalCVE').textContent = this.allCVEs.length.toLocaleString('fr-FR');
        document.getElementById('displayedCVE').textContent = this.filteredCVEs.length.toLocaleString('fr-FR');
    },
    
    /**
     * Met à jour le statut de chargement
     */
    updateLoadingStatus(status) {
        document.getElementById('loadingStatus').textContent = status;
    }
};

// Exposer APP globalement
window.APP = APP;

// Initialiser l'application quand le DOM est prêt
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => APP.init());
} else {
    APP.init();
}

