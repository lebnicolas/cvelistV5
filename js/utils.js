/**
 * Utilitaires pour l'application CVE
 */

/**
 * Formate une date ISO en format lisible
 */
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('fr-FR', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * Formate une date en format court
 */
function formatDateShort(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('fr-FR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    });
}

/**
 * Obtient la classe CSS pour la sévérité CVSS
 */
function getSeverityClass(score) {
    if (score === null || score === undefined) return 'none';
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
}

/**
 * Obtient le texte de sévérité depuis le score CVSS
 */
function getSeverityText(score) {
    if (score === null || score === undefined) return 'N/A';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
}

/**
 * Extrait le score CVSS depuis un objet CVE
 */
function extractCVSSScore(cve) {
    if (!cve.containers?.cna?.metrics) return null;
    
    for (const metric of cve.containers.cna.metrics) {
        if (metric.cvssV3_1) {
            return metric.cvssV3_1.baseScore;
        }
        if (metric.cvssV3_0) {
            return metric.cvssV3_0.baseScore;
        }
        if (metric.cvssV2) {
            return metric.cvssV2.baseScore;
        }
    }
    
    return null;
}

/**
 * Extrait la sévérité depuis un objet CVE
 */
function extractSeverity(cve) {
    if (!cve.containers?.cna?.metrics) return null;
    
    for (const metric of cve.containers.cna.metrics) {
        if (metric.cvssV3_1?.baseSeverity) {
            return metric.cvssV3_1.baseSeverity;
        }
        if (metric.cvssV3_0?.baseSeverity) {
            return metric.cvssV3_0.baseSeverity;
        }
    }
    
    // Calculer depuis le score si pas de sévérité directe
    const score = extractCVSSScore(cve);
    if (score !== null) {
        return getSeverityText(score);
    }
    
    return null;
}

/**
 * Extrait le titre depuis un objet CVE
 */
function extractTitle(cve) {
    if (cve.containers?.cna?.title) {
        return cve.containers.cna.title;
    }
    if (cve.containers?.cna?.descriptions?.[0]?.value) {
        const desc = cve.containers.cna.descriptions[0].value;
        // Prendre les premiers 100 caractères comme titre
        return desc.length > 100 ? desc.substring(0, 100) + '...' : desc;
    }
    return 'Pas de titre disponible';
}

/**
 * Extrait la description depuis un objet CVE
 */
function extractDescription(cve) {
    if (cve.containers?.cna?.descriptions?.[0]?.value) {
        return cve.containers.cna.descriptions[0].value;
    }
    return 'Pas de description disponible';
}

/**
 * Extrait les produits affectés depuis un objet CVE
 */
function extractAffectedProducts(cve) {
    const affected = [];
    if (!cve.containers?.cna?.affected) return affected;
    
    for (const item of cve.containers.cna.affected) {
        affected.push({
            vendor: item.vendor || 'N/A',
            product: item.product || 'N/A',
            versions: item.versions || []
        });
    }
    
    return affected;
}

/**
 * Extrait les références depuis un objet CVE
 */
function extractReferences(cve) {
    const references = [];
    
    // Références CNA
    if (cve.containers?.cna?.references) {
        references.push(...cve.containers.cna.references);
    }
    
    // Références ADP (CVE Program Container)
    if (cve.containers?.adp) {
        for (const adp of cve.containers.adp) {
            if (adp.title === 'CVE Program Container' && adp.references) {
                references.push(...adp.references);
            }
        }
    }
    
    return references;
}

/**
 * Extrait les solutions depuis un objet CVE
 */
function extractSolutions(cve) {
    if (cve.containers?.cna?.solutions) {
        return cve.containers.cna.solutions;
    }
    return [];
}

/**
 * Extrait le vecteur CVSS depuis un objet CVE
 */
function extractCVSSVector(cve) {
    if (!cve.containers?.cna?.metrics) return null;
    
    for (const metric of cve.containers.cna.metrics) {
        if (metric.cvssV3_1?.vectorString) {
            return metric.cvssV3_1.vectorString;
        }
        if (metric.cvssV3_0?.vectorString) {
            return metric.cvssV3_0.vectorString;
        }
        if (metric.cvssV2?.vectorString) {
            return metric.cvssV2.vectorString;
        }
    }
    
    return null;
}

/**
 * Extrait les métriques CVSS complètes depuis un objet CVE
 */
function extractCVSSMetrics(cve) {
    if (!cve.containers?.cna?.metrics) return null;
    
    for (const metric of cve.containers.cna.metrics) {
        if (metric.cvssV3_1) {
            return {
                version: '3.1',
                ...metric.cvssV3_1
            };
        }
        if (metric.cvssV3_0) {
            return {
                version: '3.0',
                ...metric.cvssV3_0
            };
        }
        if (metric.cvssV2) {
            return {
                version: '2.0',
                ...metric.cvssV2
            };
        }
    }
    
    return null;
}

/**
 * Extrait les CWE depuis un objet CVE
 */
function extractCWE(cve) {
    const cweList = [];
    if (!cve.containers?.cna?.problemTypes) return cweList;
    
    for (const problemType of cve.containers.cna.problemTypes) {
        if (problemType.descriptions) {
            for (const desc of problemType.descriptions) {
                if (desc.type === 'CWE' && desc.cweId) {
                    cweList.push({
                        id: desc.cweId,
                        description: desc.description || desc.cweId
                    });
                }
            }
        }
    }
    
    return cweList;
}

/**
 * Trie un tableau de CVE selon différents critères
 */
function sortCVEs(cves, sortBy) {
    const sorted = [...cves];
    
    switch (sortBy) {
        case 'dateDesc':
            return sorted.sort((a, b) => {
                const dateA = new Date(a.cveMetadata?.datePublished || 0);
                const dateB = new Date(b.cveMetadata?.datePublished || 0);
                return dateB - dateA;
            });
        
        case 'dateAsc':
            return sorted.sort((a, b) => {
                const dateA = new Date(a.cveMetadata?.datePublished || 0);
                const dateB = new Date(b.cveMetadata?.datePublished || 0);
                return dateA - dateB;
            });
        
        case 'cvssDesc':
            return sorted.sort((a, b) => {
                const scoreA = extractCVSSScore(a) || 0;
                const scoreB = extractCVSSScore(b) || 0;
                return scoreB - scoreA;
            });
        
        case 'cvssAsc':
            return sorted.sort((a, b) => {
                const scoreA = extractCVSSScore(a) || 0;
                const scoreB = extractCVSSScore(b) || 0;
                return scoreA - scoreB;
            });
        
        case 'idAsc':
            return sorted.sort((a, b) => {
                const idA = a.cveMetadata?.cveId || '';
                const idB = b.cveMetadata?.cveId || '';
                return idA.localeCompare(idB);
            });
        
        case 'idDesc':
            return sorted.sort((a, b) => {
                const idA = a.cveMetadata?.cveId || '';
                const idB = b.cveMetadata?.cveId || '';
                return idB.localeCompare(idA);
            });
        
        default:
            return sorted;
    }
}

/**
 * Filtre un tableau de CVE selon les critères
 */
function filterCVEs(cves, filters) {
    return cves.filter(cve => {
        // Filtre par sévérité
        if (filters.severity) {
            const severity = extractSeverity(cve);
            if (severity !== filters.severity) return false;
        }
        
        // Filtre par état
        if (filters.state) {
            if (cve.cveMetadata?.state !== filters.state) return false;
        }
        
        // Filtre par score CVSS min
        if (filters.cvssMin !== null && filters.cvssMin !== undefined && filters.cvssMin !== '') {
            const score = extractCVSSScore(cve) || 0;
            if (score < parseFloat(filters.cvssMin)) return false;
        }
        
        // Filtre par score CVSS max
        if (filters.cvssMax !== null && filters.cvssMax !== undefined && filters.cvssMax !== '') {
            const score = extractCVSSScore(cve) || 0;
            if (score > parseFloat(filters.cvssMax)) return false;
        }
        
        return true;
    });
}

/**
 * Recherche dans un tableau de CVE
 */
function searchCVEs(cves, searchTerm) {
    if (!searchTerm || searchTerm.trim() === '') return cves;
    
    const term = searchTerm.toLowerCase().trim();
    
    return cves.filter(cve => {
        const id = cve.cveMetadata?.cveId?.toLowerCase() || '';
        const title = extractTitle(cve).toLowerCase();
        const description = extractDescription(cve).toLowerCase();
        
        // Rechercher dans les produits affectés
        const affectedProducts = extractAffectedProducts(cve);
        let matchesAffectedProducts = false;
        for (const product of affectedProducts) {
            const vendor = (product.vendor || '').toLowerCase();
            const productName = (product.product || '').toLowerCase();
            if (vendor.includes(term) || productName.includes(term)) {
                matchesAffectedProducts = true;
                break;
            }
        }
        
        return id.includes(term) || title.includes(term) || description.includes(term) || matchesAffectedProducts;
    });
}

