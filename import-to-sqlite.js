/**
 * Script d'import des fichiers CVE JSON dans SQLite
 * Usage: node import-to-sqlite.js
 */

const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const CVES_DIR = path.join(__dirname, 'cves', '2025');
const DB_PATH = path.join(__dirname, 'cves.db');

/**
 * Liste récursivement tous les fichiers JSON dans un dossier
 */
function listCveFiles(dirPath) {
    const cveFiles = [];
    
    try {
        const entries = fs.readdirSync(dirPath, { withFileTypes: true });
        
        for (const entry of entries) {
            const fullPath = path.join(dirPath, entry.name);
            
            if (entry.isDirectory()) {
                // Parcourir récursivement les sous-dossiers
                const subFiles = listCveFiles(fullPath);
                cveFiles.push(...subFiles);
            } else if (entry.isFile() && entry.name.endsWith('.json') && entry.name.startsWith('CVE-2025-')) {
                cveFiles.push(fullPath);
            }
        }
    } catch (error) {
        console.error(`Erreur lors de la lecture de ${dirPath}:`, error.message);
    }
    
    return cveFiles;
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
            return metric.cvssV3_1.baseSeverity.toUpperCase();
        }
        if (metric.cvssV3_0?.baseSeverity) {
            return metric.cvssV3_0.baseSeverity.toUpperCase();
        }
    }
    
    // Calculer depuis le score si pas de sévérité directe
    const score = extractCVSSScore(cve);
    if (score !== null) {
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        return 'LOW';
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
        return desc.length > 200 ? desc.substring(0, 200) + '...' : desc;
    }
    return null;
}

/**
 * Extrait le vendor principal depuis un objet CVE
 */
function extractVendor(cve) {
    if (cve.containers?.cna?.affected?.[0]?.vendor) {
        return cve.containers.cna.affected[0].vendor.toLowerCase();
    }
    return null;
}

/**
 * Importe un fichier CVE dans la base de données
 */
function importCVE(db, filePath) {
    try {
        const fileContent = fs.readFileSync(filePath, 'utf8');
        const cve = JSON.parse(fileContent);
        
        const cveId = cve.cveMetadata?.cveId;
        if (!cveId) {
            console.warn(`Fichier sans cveId: ${filePath}`);
            return false;
        }
        
        const datePublished = cve.cveMetadata?.datePublished || null;
        const state = cve.cveMetadata?.state || null;
        const cvssScore = extractCVSSScore(cve);
        const severity = extractSeverity(cve);
        const title = extractTitle(cve);
        const vendor = extractVendor(cve);
        const jsonData = JSON.stringify(cve);
        
        const stmt = db.prepare(`
            INSERT OR REPLACE INTO cves (
                cveId, datePublished, state, cvssScore, severity, title, vendor, jsonData, lastUpdated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        
        stmt.run(
            cveId,
            datePublished,
            state,
            cvssScore,
            severity,
            title,
            vendor,
            jsonData,
            new Date().toISOString()
        );
        
        return true;
    } catch (error) {
        console.error(`Erreur lors de l'import de ${filePath}:`, error.message);
        return false;
    }
}

/**
 * Fonction principale d'import
 */
function main() {
    console.log('=== Import des CVE dans SQLite ===\n');
    
    // Supprimer l'ancienne base si elle existe
    if (fs.existsSync(DB_PATH)) {
        console.log('Suppression de l\'ancienne base de données...');
        fs.unlinkSync(DB_PATH);
    }
    
    // Créer/ouvrir la base de données
    console.log('Création de la base de données SQLite...');
    const db = new Database(DB_PATH);
    
    // Créer la table avec index
    console.log('Création de la table et des index...');
    db.exec(`
        CREATE TABLE IF NOT EXISTS cves (
            cveId TEXT PRIMARY KEY,
            datePublished TEXT,
            state TEXT,
            cvssScore REAL,
            severity TEXT,
            title TEXT,
            vendor TEXT,
            jsonData TEXT NOT NULL,
            lastUpdated TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_datePublished ON cves(datePublished);
        CREATE INDEX IF NOT EXISTS idx_state ON cves(state);
        CREATE INDEX IF NOT EXISTS idx_cvssScore ON cves(cvssScore);
        CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity);
        CREATE INDEX IF NOT EXISTS idx_vendor ON cves(vendor);
    `);
    
    // Lister tous les fichiers CVE
    console.log('Recherche des fichiers CVE...');
    const cveFiles = listCveFiles(CVES_DIR);
    console.log(`${cveFiles.length} fichiers CVE trouvés\n`);
    
    if (cveFiles.length === 0) {
        console.error('Aucun fichier CVE trouvé !');
        db.close();
        process.exit(1);
    }
    
    // Importer les fichiers
    console.log('Import des fichiers CVE...');
    const startTime = Date.now();
    let imported = 0;
    let errors = 0;
    const total = cveFiles.length;
    
    // Transaction pour améliorer les performances
    const transaction = db.transaction((files) => {
        for (const filePath of files) {
            if (importCVE(db, filePath)) {
                imported++;
            } else {
                errors++;
            }
            
            // Afficher la progression tous les 100 fichiers
            if ((imported + errors) % 100 === 0) {
                const progress = ((imported + errors) / total * 100).toFixed(1);
                process.stdout.write(`\rProgression: ${imported + errors}/${total} (${progress}%) - ${imported} importés, ${errors} erreurs`);
            }
        }
    });
    
    // Exécuter la transaction
    transaction(cveFiles);
    
    // Afficher le résultat final
    console.log(`\n\n=== Import terminé ===`);
    console.log(`Fichiers traités: ${imported + errors}/${total}`);
    console.log(`Importés avec succès: ${imported}`);
    console.log(`Erreurs: ${errors}`);
    
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`Temps écoulé: ${duration}s`);
    console.log(`Vitesse: ${(imported / duration).toFixed(0)} CVE/s\n`);
    
    // Vérifier le nombre de CVE dans la base
    const count = db.prepare('SELECT COUNT(*) as count FROM cves').get();
    console.log(`Total de CVE dans la base: ${count.count}`);
    
    // Fermer la base de données
    db.close();
    console.log('\n✓ Base de données créée avec succès !');
    console.log(`Fichier: ${DB_PATH}`);
}

// Exécuter l'import
main();

