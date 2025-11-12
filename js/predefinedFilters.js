/**
 * Gestion des filtres prédéfinis
 */

const PREDEFINED_FILTERS = {
    filters: [],
    
    /**
     * Charge les filtres prédéfinis depuis le serveur
     */
    async loadFilters() {
        try {
            const response = await fetch('/api/predefined-filters');
            if (response.ok) {
                const data = await response.json();
                this.filters = data.filters || [];
                this.renderFilters();
            } else {
                console.warn('Impossible de charger les filtres prédéfinis, utilisation des valeurs par défaut');
                this.filters = ['Dell', 'vCenter', 'ESXi'];
                this.renderFilters();
            }
        } catch (error) {
            console.error('Erreur lors du chargement des filtres prédéfinis:', error);
            // Valeurs par défaut en cas d'erreur
            this.filters = ['Dell', 'vCenter', 'ESXi'];
            this.renderFilters();
        }
    },
    
    /**
     * Sauvegarde les filtres prédéfinis sur le serveur
     */
    async saveFilters() {
        try {
            const response = await fetch('/api/predefined-filters', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ filters: this.filters })
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: `Erreur HTTP ${response.status}` }));
                throw new Error(errorData.error || `Erreur HTTP ${response.status}`);
            }
            
            const result = await response.json();
            console.log('Filtres prédéfinis sauvegardés avec succès');
            return true;
        } catch (error) {
            console.error('Erreur lors de la sauvegarde des filtres prédéfinis:', error);
            alert(`Erreur lors de la sauvegarde des filtres prédéfinis: ${error.message}`);
            return false;
        }
    },
    
    /**
     * Ajoute un filtre prédéfini
     */
    async addFilter(name) {
        const trimmedName = name.trim();
        if (!trimmedName) {
            alert('Le nom du filtre ne peut pas être vide');
            return false;
        }
        
        if (this.filters.includes(trimmedName)) {
            alert(`Le filtre "${trimmedName}" existe déjà`);
            return false;
        }
        
        this.filters.push(trimmedName);
        this.renderFilters();
        return await this.saveFilters();
    },
    
    /**
     * Supprime un filtre prédéfini
     */
    async removeFilter(name) {
        const index = this.filters.indexOf(name);
        if (index > -1) {
            // Sauvegarder l'état actuel pour pouvoir le restaurer en cas d'erreur
            const previousFilters = [...this.filters];
            
            // Supprimer le filtre
            this.filters.splice(index, 1);
            this.renderFilters();
            
            // Sauvegarder sur le serveur
            const success = await this.saveFilters();
            
            if (!success) {
                // Restaurer l'état précédent en cas d'erreur
                this.filters = previousFilters;
                this.renderFilters();
                return false;
            }
            
            return true;
        }
        return false;
    },
    
    /**
     * Affiche la liste des filtres prédéfinis dans le DOM
     */
    renderFilters() {
        const container = document.getElementById('predefinedFiltersList');
        if (!container) {
            return;
        }
        
        container.innerHTML = '';
        
        this.filters.forEach(filterName => {
            const filterItem = document.createElement('div');
            filterItem.className = 'predefined-filter-item';
            filterItem.innerHTML = `
                <button class="predefined-filter-btn" data-filter="${filterName}">${filterName}</button>
                <button class="remove-filter-btn" data-filter="${filterName}" title="Supprimer ce filtre">×</button>
            `;
            container.appendChild(filterItem);
        });
        
        // Attacher les event listeners
        container.querySelectorAll('.predefined-filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const filterName = e.target.getAttribute('data-filter');
                this.applyPredefinedFilter(filterName);
            });
        });
        
        container.querySelectorAll('.remove-filter-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const filterName = e.target.getAttribute('data-filter');
                if (confirm(`Voulez-vous supprimer le filtre "${filterName}" ?`)) {
                    await this.removeFilter(filterName);
                }
            });
        });
    },
    
    /**
     * Applique un filtre prédéfini en remplaçant tous les autres filtres prédéfinis actifs
     * Retire tous les filtres prédéfinis existants et ajoute celui cliqué
     */
    applyPredefinedFilter(name) {
        if (!window.APP) {
            console.warn('APP n\'est pas disponible');
            return;
        }
        
        if (!window.APP.activeFilters || !window.APP.activeFilters.search) {
            // Aucun filtre actif, ajouter simplement le nouveau
            if (window.APP.addActiveFilter) {
                window.APP.addActiveFilter('search', name, name);
            }
            return;
        }
        
        // Retirer tous les filtres prédéfinis actifs (ceux qui sont dans la liste des filtres prédéfinis)
        const filtersToRemove = [];
        window.APP.activeFilters.search.forEach(filter => {
            if (this.filters.includes(filter.value)) {
                filtersToRemove.push(filter.value);
            }
        });
        
        // Retirer tous les filtres prédéfinis
        if (window.APP.removeActiveFilter) {
            filtersToRemove.forEach(filterValue => {
                window.APP.removeActiveFilter('search', filterValue);
            });
        }
        
        // Ajouter le nouveau filtre (même s'il était déjà là, il sera retiré puis réajouté)
        if (window.APP.addActiveFilter) {
            window.APP.addActiveFilter('search', name, name);
        }
    },
    
    /**
     * Initialise le module
     */
    async init() {
        // Event listener pour le bouton d'ajout
        const addBtn = document.getElementById('addFilterBtn');
        if (addBtn) {
            addBtn.addEventListener('click', () => {
                const filterName = prompt('Entrez le nom du nouveau filtre prédéfini:');
                if (filterName) {
                    this.addFilter(filterName);
                }
            });
        }
        
        // Charger les filtres au démarrage
        await this.loadFilters();
    }
};

// Initialiser au chargement de la page
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        PREDEFINED_FILTERS.init();
    });
} else {
    PREDEFINED_FILTERS.init();
}

