/**
 * Rendu de l'interface CVE
 * Gère l'affichage de la liste et des détails
 */

const CVE_RENDERER = {
    itemsPerPage: 50,
    currentPage: 1,
    
    /**
     * Affiche la liste des CVE
     */
    renderCVEList(cves, page = 1) {
        this.currentPage = page;
        const container = document.getElementById('cveList');
        
        if (!cves || cves.length === 0) {
            container.innerHTML = '<div class="loading-message">Aucun CVE trouvé</div>';
            return;
        }
        
        // Calculer la pagination
        const totalPages = Math.ceil(cves.length / this.itemsPerPage);
        const startIndex = (page - 1) * this.itemsPerPage;
        const endIndex = startIndex + this.itemsPerPage;
        const pageCVEs = cves.slice(startIndex, endIndex);
        
        // Rendre les éléments
        const html = pageCVEs.map(cve => this.renderCVEItem(cve)).join('');
        container.innerHTML = html;
        
        // Rendre la pagination
        this.renderPagination(page, totalPages, cves.length);
        
        // Ajouter les event listeners
        this.attachItemListeners();
    },
    
    /**
     * Rendre un élément CVE individuel
     */
    renderCVEItem(cve) {
        const cveId = cve.cveMetadata?.cveId || 'N/A';
        const title = extractTitle(cve);
        const state = cve.cveMetadata?.state || 'UNKNOWN';
        const datePublished = cve.cveMetadata?.datePublished;
        const cvssScore = extractCVSSScore(cve);
        const severity = extractSeverity(cve);
        const assigner = cve.cveMetadata?.assignerShortName || 'N/A';
        
        const cvssClass = cvssScore !== null ? getSeverityClass(cvssScore) : 'none';
        const cvssDisplay = cvssScore !== null ? cvssScore.toFixed(1) : 'N/A';
        const severityClass = severity ? severity.toLowerCase() : 'none';
        const stateClass = state.toLowerCase();
        
        return `
            <div class="cve-item" data-cve-id="${cveId}">
                <div class="cve-header">
                    <div>
                        <div class="cve-id">${cveId}</div>
                        <div class="cve-title">${this.escapeHtml(title)}</div>
                    </div>
                    <div class="cve-badges">
                        <span class="badge badge-state ${stateClass}">${state}</span>
                        ${severity ? `<span class="badge badge-severity ${severityClass}">${severity}</span>` : ''}
                        ${cvssScore !== null ? `<span class="cvss-score ${cvssClass}">CVSS: ${cvssDisplay}</span>` : ''}
                    </div>
                </div>
                <div class="cve-meta">
                    <div class="cve-meta-item">
                        <span>📅</span>
                        <span>${formatDateShort(datePublished)}</span>
                    </div>
                    <div class="cve-meta-item">
                        <span>🏢</span>
                        <span>${this.escapeHtml(assigner)}</span>
                    </div>
                </div>
            </div>
        `;
    },
    
    /**
     * Rendre la pagination
     */
    renderPagination(currentPage, totalPages, totalItems) {
        const container = document.getElementById('pagination');
        
        if (totalPages <= 1) {
            container.innerHTML = '';
            return;
        }
        
        let html = '';
        
        // Bouton précédent
        html += `<button ${currentPage === 1 ? 'disabled' : ''} data-page="${currentPage - 1}">‹ Précédent</button>`;
        
        // Numéros de page
        const maxVisible = 5;
        let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
        let endPage = Math.min(totalPages, startPage + maxVisible - 1);
        
        if (endPage - startPage < maxVisible - 1) {
            startPage = Math.max(1, endPage - maxVisible + 1);
        }
        
        if (startPage > 1) {
            html += `<button data-page="1">1</button>`;
            if (startPage > 2) {
                html += `<span>...</span>`;
            }
        }
        
        for (let i = startPage; i <= endPage; i++) {
            html += `<button class="${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
        }
        
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                html += `<span>...</span>`;
            }
            html += `<button data-page="${totalPages}">${totalPages}</button>`;
        }
        
        // Bouton suivant
        html += `<button ${currentPage === totalPages ? 'disabled' : ''} data-page="${currentPage + 1}">Suivant ›</button>`;
        
        // Info de pagination
        const startItem = (currentPage - 1) * this.itemsPerPage + 1;
        const endItem = Math.min(currentPage * this.itemsPerPage, totalItems);
        html += `<span class="pagination-info">${startItem}-${endItem} sur ${totalItems}</span>`;
        
        container.innerHTML = html;
        
        // Ajouter les event listeners
        container.querySelectorAll('button[data-page]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const page = parseInt(e.target.dataset.page);
                if (page !== currentPage && page >= 1 && page <= totalPages) {
                    window.APP.goToPage(page);
                }
            });
        });
    },
    
    /**
     * Attacher les listeners aux éléments CVE
     */
    attachItemListeners() {
        document.querySelectorAll('.cve-item').forEach(item => {
            item.addEventListener('click', () => {
                const cveId = item.dataset.cveId;
                window.APP.showCVEDetails(cveId);
            });
        });
    },
    
    /**
     * Affiche les détails d'un CVE dans une modal
     */
    renderCVEDetails(cve) {
        const container = document.getElementById('cveDetails');
        const modal = document.getElementById('cveModal');
        
        if (!cve) {
            container.innerHTML = '<div class="loading-message">CVE non trouvé</div>';
            return;
        }
        
        const cveId = cve.cveMetadata?.cveId || 'N/A';
        const title = extractTitle(cve);
        const description = extractDescription(cve);
        const state = cve.cveMetadata?.state || 'UNKNOWN';
        const dateReserved = cve.cveMetadata?.dateReserved;
        const datePublished = cve.cveMetadata?.datePublished;
        const dateUpdated = cve.cveMetadata?.dateUpdated;
        const assigner = cve.cveMetadata?.assignerShortName || 'N/A';
        const cvssScore = extractCVSSScore(cve);
        const severity = extractSeverity(cve);
        const cvssMetrics = extractCVSSMetrics(cve);
        const cvssVector = extractCVSSVector(cve);
        const affectedProducts = extractAffectedProducts(cve);
        const references = extractReferences(cve);
        const solutions = extractSolutions(cve);
        const cweList = extractCWE(cve);
        
        const cvssClass = cvssScore !== null ? getSeverityClass(cvssScore) : 'none';
        const cvssDisplay = cvssScore !== null ? cvssScore.toFixed(1) : 'N/A';
        const severityClass = severity ? severity.toLowerCase() : 'none';
        
        let html = `
            <div class="cve-detail-section">
                <h2>${cveId}</h2>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">État</span>
                        <span class="detail-value"><span class="badge badge-state ${state.toLowerCase()}">${state}</span></span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Sévérité</span>
                        <span class="detail-value">
                            ${severity ? `<span class="badge badge-severity ${severityClass}">${severity}</span>` : 'N/A'}
                        </span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Score CVSS</span>
                        <span class="detail-value">
                            ${cvssScore !== null ? `<span class="cvss-score ${cvssClass}">${cvssDisplay}</span>` : 'N/A'}
                        </span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Assigné par</span>
                        <span class="detail-value">${this.escapeHtml(assigner)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Date réservée</span>
                        <span class="detail-value">${formatDate(dateReserved)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Date publiée</span>
                        <span class="detail-value">${formatDate(datePublished)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Dernière mise à jour</span>
                        <span class="detail-value">${formatDate(dateUpdated)}</span>
                    </div>
                </div>
            </div>
            
            <div class="cve-detail-section">
                <h2>Titre</h2>
                <p>${this.escapeHtml(title)}</p>
            </div>
            
            <div class="cve-detail-section">
                <h2>Description</h2>
                <p>${this.escapeHtml(description).replace(/\n/g, '<br>')}</p>
            </div>
        `;
        
        // CWE
        if (cweList.length > 0) {
            html += `
                <div class="cve-detail-section">
                    <h2>Weakness Enumeration (CWE)</h2>
                    <ul class="affected-list">
                        ${cweList.map(cwe => `
                            <li class="affected-item">
                                <strong>${cwe.id}:</strong> ${this.escapeHtml(cwe.description)}
                            </li>
                        `).join('')}
                    </ul>
                </div>
            `;
        }
        
        // Produits affectés
        if (affectedProducts.length > 0) {
            html += `
                <div class="cve-detail-section">
                    <h2>Produits affectés</h2>
                    <ul class="affected-list">
                        ${affectedProducts.map(product => {
                            let versionsHtml = '';
                            if (product.versions && product.versions.length > 0) {
                                versionsHtml = '<ul style="margin-top: 0.5rem; margin-left: 1.5rem;">';
                                product.versions.forEach(version => {
                                    const versionInfo = [];
                                    if (version.version) versionInfo.push(`Version: ${version.version}`);
                                    if (version.lessThan) versionInfo.push(`< ${version.lessThan}`);
                                    if (version.lessThanOrEqual) versionInfo.push(`<= ${version.lessThanOrEqual}`);
                                    if (version.greaterThan) versionInfo.push(`> ${version.greaterThan}`);
                                    if (version.greaterThanOrEqual) versionInfo.push(`>= ${version.greaterThanOrEqual}`);
                                    if (version.status) versionInfo.push(`[${version.status}]`);
                                    versionsHtml += `<li style="margin-top: 0.25rem;">${versionInfo.join(' ')}</li>`;
                                });
                                versionsHtml += '</ul>';
                            }
                            return `
                                <li class="affected-item">
                                    <strong>${this.escapeHtml(product.vendor)}</strong> - ${this.escapeHtml(product.product)}
                                    ${versionsHtml}
                                </li>
                            `;
                        }).join('')}
                    </ul>
                </div>
            `;
        }
        
        // Métriques CVSS détaillées
        if (cvssMetrics) {
            html += `
                <div class="cve-detail-section">
                    <h2>Métriques CVSS ${cvssMetrics.version}</h2>
                    <div class="cvss-details">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Vecteur d'attaque</span>
                                <span class="detail-value">${cvssMetrics.attackVector || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Complexité d'attaque</span>
                                <span class="detail-value">${cvssMetrics.attackComplexity || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Privilèges requis</span>
                                <span class="detail-value">${cvssMetrics.privilegesRequired || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Interaction utilisateur</span>
                                <span class="detail-value">${cvssMetrics.userInteraction || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Portée</span>
                                <span class="detail-value">${cvssMetrics.scope || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Impact confidentialité</span>
                                <span class="detail-value">${cvssMetrics.confidentialityImpact || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Impact intégrité</span>
                                <span class="detail-value">${cvssMetrics.integrityImpact || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Impact disponibilité</span>
                                <span class="detail-value">${cvssMetrics.availabilityImpact || 'N/A'}</span>
                            </div>
                        </div>
                        ${cvssVector ? `<div class="cvss-vector">${cvssVector}</div>` : ''}
                    </div>
                </div>
            `;
        }
        
        // Solutions
        if (solutions.length > 0) {
            html += `
                <div class="cve-detail-section">
                    <h2>Solutions</h2>
                    ${solutions.map(solution => `
                        <div style="margin-bottom: 1rem;">
                            <p>${this.escapeHtml(solution.value || '').replace(/\n/g, '<br>')}</p>
                        </div>
                    `).join('')}
                </div>
            `;
        }
        
        // Références
        if (references.length > 0) {
            html += `
                <div class="cve-detail-section">
                    <h2>Références</h2>
                    <ul class="references-list">
                        ${references.map(ref => `
                            <li>
                                <a href="${this.escapeHtml(ref.url)}" target="_blank" rel="noopener noreferrer">
                                    ${this.escapeHtml(ref.url)}
                                </a>
                                ${ref.tags && ref.tags.length > 0 ? ` <span style="color: var(--text-secondary); font-size: 0.875rem;">[${ref.tags.join(', ')}]</span>` : ''}
                            </li>
                        `).join('')}
                    </ul>
                </div>
            `;
        }
        
        container.innerHTML = html;
        modal.style.display = 'block';
    },
    
    /**
     * Échappe le HTML pour éviter les injections XSS
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },
    
    /**
     * Ferme la modal
     */
    closeModal() {
        const modal = document.getElementById('cveModal');
        modal.style.display = 'none';
    }
};

