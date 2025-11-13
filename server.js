/**
 * Serveur HTTP avec génération automatique de l'index CVE et API SQLite
 * Usage: node server.js [port]
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');

const PORT = process.argv[2] || 8080;
const CVES_DIR = path.join(__dirname, 'cves', '2025');
const INDEX_FILE = path.join(__dirname, 'cves', '2025', 'index.json');
const DB_PATH = path.join(__dirname, 'cves.db');
const PREDEFINED_FILTERS_FILE = path.join(__dirname, 'data', 'predefined-filters.json');
const SENT_CVES_FILE = path.join(__dirname, 'data', 'sent-cves.json');
const EMAIL_RECIPIENTS_FILE = path.join(__dirname, 'data', 'email-recipients.json');

// Configuration SMTP
const SMTP_HOST = '10.10.22.3';
const SMTP_PORT = 25;
const EMAIL_TO = 'nicolas.lebon@atos.net';
const EMAIL_INTERVAL = process.env.EMAIL_INTERVAL ? parseInt(process.env.EMAIL_INTERVAL) : 24 * 60 * 60 * 1000; // 24h par défaut

let db = null;

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
                // Ajouter le fichier CVE
                const relativePath = path.relative(CVES_DIR, fullPath);
                cveFiles.push({
                    cveId: entry.name.replace('.json', ''),
                    path: relativePath.replace(/\\/g, '/'), // Normaliser les séparateurs
                    fullPath: fullPath
                });
            }
        }
    } catch (error) {
        console.error(`Erreur lors de la lecture de ${dirPath}:`, error.message);
    }
    
    return cveFiles;
}

/**
 * Génère l'index des CVE
 */
function generateIndex() {
    console.log('Génération de l\'index des CVE...');
    const startTime = Date.now();
    
    try {
        const cveFiles = listCveFiles(CVES_DIR);
        
        // Trier par ID CVE
        cveFiles.sort((a, b) => {
            const numA = parseInt(a.cveId.match(/CVE-2025-(\d+)/)?.[1] || '0');
            const numB = parseInt(b.cveId.match(/CVE-2025-(\d+)/)?.[1] || '0');
            return numA - numB;
        });
        
        // Créer l'objet index
        const index = {
            generatedAt: new Date().toISOString(),
            totalCves: cveFiles.length,
            cveIds: cveFiles.map(f => f.cveId),
            cvePaths: {}
        };
        
        // Créer un mapping CVE ID -> chemin
        cveFiles.forEach(file => {
            index.cvePaths[file.cveId] = file.path;
        });
        
        // Écrire le fichier index
        fs.writeFileSync(INDEX_FILE, JSON.stringify(index, null, 2), 'utf8');
        
        const duration = ((Date.now() - startTime) / 1000).toFixed(2);
        console.log(`✓ Index généré avec succès !`);
        console.log(`  - ${cveFiles.length} fichiers CVE trouvés`);
        console.log(`  - Fichier créé: ${INDEX_FILE}`);
        console.log(`  - Temps écoulé: ${duration}s\n`);
        
        return true;
    } catch (error) {
        console.error('Erreur lors de la génération de l\'index:', error);
        return false;
    }
}

/**
 * Détermine le type MIME d'un fichier
 */
function getMimeType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
        '.html': 'text/html',
        '.css': 'text/css',
        '.js': 'application/javascript',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.gif': 'image/gif',
        '.svg': 'image/svg+xml',
        '.ico': 'image/x-icon'
    };
    return mimeTypes[ext] || 'application/octet-stream';
}

/**
 * Serve les fichiers statiques
 */
function serveFile(filePath, res) {
    try {
        const fullPath = path.join(__dirname, filePath);
        
        // Sécurité: empêcher l'accès en dehors du répertoire
        if (!fullPath.startsWith(__dirname)) {
            res.writeHead(403);
            res.end('Forbidden');
            return;
        }
        
        if (!fs.existsSync(fullPath)) {
            res.writeHead(404);
            res.end('Not Found');
            return;
        }
        
        const stats = fs.statSync(fullPath);
        if (stats.isDirectory()) {
            res.writeHead(403);
            res.end('Directory listing not allowed');
            return;
        }
        
        const content = fs.readFileSync(fullPath);
        const mimeType = getMimeType(fullPath);
        
        res.writeHead(200, {
            'Content-Type': mimeType,
            'Content-Length': content.length,
            'Cache-Control': 'public, max-age=3600'
        });
        res.end(content);
    } catch (error) {
        console.error(`Erreur lors du service de ${filePath}:`, error);
        res.writeHead(500);
        res.end('Internal Server Error');
    }
}

/**
 * Ouvre la base de données SQLite
 */
function openDatabase() {
    if (!fs.existsSync(DB_PATH)) {
        console.warn(`⚠ Base de données SQLite non trouvée: ${DB_PATH}`);
        console.warn('  Exécutez "npm run import" pour créer la base de données.\n');
        return null;
    }
    
    try {
        db = new Database(DB_PATH, { readonly: true });
        console.log(`✓ Base de données SQLite ouverte: ${DB_PATH}`);
        
        // Vérifier le nombre de CVE
        const count = db.prepare('SELECT COUNT(*) as count FROM cves').get();
        console.log(`  - ${count.count} CVE disponibles\n`);
        
        return db;
    } catch (error) {
        console.error('Erreur lors de l\'ouverture de la base de données:', error.message);
        return null;
    }
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
    return 'Pas de titre disponible';
}

/**
 * Charge les CVE déjà envoyées depuis le fichier de suivi
 */
function loadSentCVEs() {
    try {
        if (!fs.existsSync(SENT_CVES_FILE)) {
            // Créer le fichier avec une structure vide si il n'existe pas
            const emptyData = {};
            const dataDir = path.dirname(SENT_CVES_FILE);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }
            fs.writeFileSync(SENT_CVES_FILE, JSON.stringify(emptyData, null, 2), 'utf8');
            return emptyData;
        }
        
        const content = fs.readFileSync(SENT_CVES_FILE, 'utf8');
        return JSON.parse(content);
    } catch (error) {
        console.error('Erreur lors du chargement des CVE envoyées:', error);
        return {};
    }
}

/**
 * Sauvegarde les CVE envoyées dans le fichier de suivi
 */
function saveSentCVEs(sentCVEs) {
    try {
        const dataDir = path.dirname(SENT_CVES_FILE);
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
        fs.writeFileSync(SENT_CVES_FILE, JSON.stringify(sentCVEs, null, 2), 'utf8');
    } catch (error) {
        console.error('Erreur lors de la sauvegarde des CVE envoyées:', error);
        throw error;
    }
}

/**
 * Récupère la date de publication maximale des CVE déjà envoyées pour un filtre
 */
function getMaxDateForSentCVEs(filterName) {
    if (!db) {
        return null;
    }
    
    try {
        const sentCVEs = loadSentCVEs();
        const sentForFilter = sentCVEs[filterName] || [];
        
        if (sentForFilter.length === 0) {
            return null;
        }
        
        // Récupérer les dates de publication des CVE envoyées depuis la base de données
        const placeholders = sentForFilter.map(() => '?').join(',');
        const stmt = db.prepare(`
            SELECT MAX(datePublished) as maxDate
            FROM cves
            WHERE cveId IN (${placeholders})
        `);
        
        const result = stmt.get(...sentForFilter);
        return result && result.maxDate ? result.maxDate : null;
    } catch (error) {
        console.error(`Erreur lors de la récupération de la date maximale pour le filtre ${filterName}:`, error);
        return null;
    }
}

/**
 * Marque des CVE comme envoyées pour un filtre donné
 */
function markCVEsAsSent(filterName, cveIds) {
    const sentCVEs = loadSentCVEs();
    
    if (!sentCVEs[filterName]) {
        sentCVEs[filterName] = [];
    }
    
    // Ajouter les nouvelles CVE sans doublons
    for (const cveId of cveIds) {
        if (!sentCVEs[filterName].includes(cveId)) {
            sentCVEs[filterName].push(cveId);
        }
    }
    
    saveSentCVEs(sentCVEs);
}

/**
 * Récupère les 3 dernières CVE pour un filtre donné, en excluant celles déjà envoyées
 * et en ne récupérant que celles dont la date de publication est >= à la date maximale des CVE déjà envoyées
 */
function getLatestCVEsForFilter(filterName, excludeSent = true) {
    if (!db) {
        throw new Error('Base de données non disponible');
    }
    
    try {
        const searchTerm = `%${filterName}%`;
        const searchTermLower = `%${filterName.toLowerCase()}%`;
        
        // Recherche dans : title, cveId, vendor, description, et produits affectés (vendor et product)
        // La recherche dans les produits affectés utilise json_each pour parcourir tous les éléments du tableau
        let whereClause = `(
            title LIKE ? OR 
            cveId LIKE ? OR 
            vendor LIKE ? OR
            LOWER(json_extract(jsonData, '$.containers.cna.descriptions[0].value')) LIKE ? OR
            EXISTS (
                SELECT 1 
                FROM json_each(json_extract(jsonData, '$.containers.cna.affected'))
                WHERE LOWER(json_extract(value, '$.vendor')) LIKE ? 
                   OR LOWER(json_extract(value, '$.product')) LIKE ?
            )
        )`;
        let params = [searchTerm, searchTerm, searchTerm, searchTermLower, searchTermLower, searchTermLower];
        
        // Exclure les CVE déjà envoyées si demandé
        if (excludeSent) {
            const sentCVEs = loadSentCVEs();
            const sentForFilter = sentCVEs[filterName] || [];
            
            if (sentForFilter.length > 0) {
                // Construire la clause NOT IN pour exclure les CVE déjà envoyées
                const placeholders = sentForFilter.map(() => '?').join(',');
                whereClause += ` AND cveId NOT IN (${placeholders})`;
                params = params.concat(sentForFilter);
            }
            
            // Récupérer la date maximale des CVE déjà envoyées
            const maxDate = getMaxDateForSentCVEs(filterName);
            if (maxDate) {
                // Ne récupérer que les CVE dont la date de publication est >= à la date maximale
                // Cela garantit qu'on ne récupère pas de CVE plus anciennes que celles déjà envoyées
                whereClause += ` AND datePublished >= ?`;
                params.push(maxDate);
            }
        }
        
        const selectStmt = db.prepare(`
            SELECT jsonData 
            FROM cves 
            WHERE ${whereClause}
            ORDER BY datePublished DESC
            LIMIT 3
        `);
        
        const results = selectStmt.all(...params);
        return results.map(row => JSON.parse(row.jsonData));
    } catch (error) {
        console.error(`Erreur lors de la récupération des CVE pour le filtre ${filterName}:`, error);
        return [];
    }
}

/**
 * Formate les résultats en HTML pour l'email
 */
function formatEmailContent(filterResults) {
    const date = new Date().toLocaleDateString('fr-FR', { 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric' 
    });
    
    let html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            padding: 10px;
            background-color: #ecf0f1;
            border-left: 4px solid #3498db;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th {
            background-color: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .cve-id {
            font-weight: bold;
            color: #2980b9;
        }
        .severity-critical {
            background-color: #e74c3c;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .severity-high {
            background-color: #e67e22;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .severity-medium {
            background-color: #f39c12;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .severity-low {
            background-color: #27ae60;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .severity-none {
            background-color: #95a5a6;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
        }
        .cvss-score {
            font-weight: bold;
            font-size: 1.1em;
        }
        .no-cve {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            font-style: italic;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <h1>Rapport CVE - ${date}</h1>
    <p>Ce rapport contient les nouvelles CVE (non encore envoyées) pour chaque filtre prédéfini.</p>
`;
    
    for (const filterResult of filterResults) {
        const filterName = filterResult.filterName;
        const cves = filterResult.cves;
        
        html += `<h2>Filtre: ${filterName}</h2>`;
        
        if (cves.length === 0) {
            html += `<div class="no-cve">Aucune CVE trouvée pour ce filtre.</div>`;
        } else {
            html += `
            <table>
                <thead>
                    <tr>
                        <th>ID CVE</th>
                        <th>Titre</th>
                        <th>Date de publication</th>
                        <th>Score CVSS</th>
                        <th>Sévérité</th>
                    </tr>
                </thead>
                <tbody>
            `;
            
            for (const cve of cves) {
                const cveId = cve.cveMetadata?.cveId || 'N/A';
                const title = extractTitle(cve);
                const datePublished = cve.cveMetadata?.datePublished || 'N/A';
                const cvssScore = extractCVSSScore(cve);
                const severity = extractSeverity(cve);
                
                const severityClass = severity ? `severity-${severity.toLowerCase()}` : 'severity-none';
                const severityText = severity || 'N/A';
                const cvssDisplay = cvssScore !== null ? cvssScore.toFixed(1) : 'N/A';
                
                html += `
                    <tr>
                        <td class="cve-id">${cveId}</td>
                        <td>${title}</td>
                        <td>${datePublished}</td>
                        <td class="cvss-score">${cvssDisplay}</td>
                        <td><span class="${severityClass}">${severityText}</span></td>
                    </tr>
                `;
            }
            
            html += `
                </tbody>
            </table>
            `;
        }
    }
    
    html += `
    <div class="footer">
        <p>Rapport généré automatiquement le ${new Date().toLocaleString('fr-FR')}</p>
    </div>
</body>
</html>
    `;
    
    return html;
}

/**
 * Envoie l'email avec les CVE pour tous les filtres prédéfinis
 */
async function sendCVEEmail() {
    try {
        // Charger les filtres prédéfinis
        if (!fs.existsSync(PREDEFINED_FILTERS_FILE)) {
            throw new Error('Fichier de filtres prédéfinis non trouvé');
        }
        
        const filtersData = JSON.parse(fs.readFileSync(PREDEFINED_FILTERS_FILE, 'utf8'));
        const filters = filtersData.filters || [];
        
        if (filters.length === 0) {
            console.log('Aucun filtre prédéfini trouvé, aucun email envoyé');
            return { success: false, message: 'Aucun filtre prédéfini trouvé' };
        }
        
        // Charger les CVE déjà envoyées
        const sentCVEs = loadSentCVEs();
        
        // Récupérer les nouvelles CVE pour chaque filtre (excluant celles déjà envoyées)
        const filterResults = [];
        const newCVEsToMark = {}; // Pour sauvegarder après l'envoi réussi
        
        for (const filterName of filters) {
            const cves = getLatestCVEsForFilter(filterName, true); // excludeSent = true par défaut
            
            // Extraire les IDs des nouvelles CVE pour ce filtre
            // getLatestCVEsForFilter a déjà exclu les CVE envoyées, donc toutes les CVE retournées sont nouvelles
            const newCveIds = cves
                .map(cve => cve.cveMetadata?.cveId)
                .filter(cveId => cveId); // Filtrer les valeurs nulles/undefined
            
            if (newCveIds.length > 0) {
                newCVEsToMark[filterName] = newCveIds;
            }
            
            filterResults.push({
                filterName: filterName,
                cves: cves
            });
        }
        
        // Vérifier s'il y a de nouvelles CVE à envoyer
        const hasNewCVEs = Object.keys(newCVEsToMark).length > 0 && 
            Object.values(newCVEsToMark).some(ids => ids.length > 0);
        
        if (!hasNewCVEs) {
            console.log('Aucune nouvelle CVE à envoyer');
            return { 
                success: true, 
                message: 'Aucune nouvelle CVE à envoyer',
                newCVEsCount: 0
            };
        }
        
        // Formater le contenu HTML
        const htmlContent = formatEmailContent(filterResults);
        
        // Configurer le transporteur SMTP
        const transporter = nodemailer.createTransport({
            host: SMTP_HOST,
            port: SMTP_PORT,
            secure: false, // false pour port 25
            auth: false, // Pas d'authentification
            tls: {
                rejectUnauthorized: false
            }
        });
        
        // Charger la liste des destinataires
        let recipients = [];
        if (fs.existsSync(EMAIL_RECIPIENTS_FILE)) {
            const recipientsData = JSON.parse(fs.readFileSync(EMAIL_RECIPIENTS_FILE, 'utf8'));
            recipients = recipientsData.recipients || [];
        } else {
            // Valeur par défaut si le fichier n'existe pas
            recipients = ['nicolas.lebon@atos.net'];
        }
        
        if (recipients.length === 0) {
            throw new Error('Aucun destinataire configuré');
        }
        
        // Préparer l'email
        const date = new Date().toLocaleDateString('fr-FR', { 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric' 
        });
        
        const mailOptions = {
            from: 'cve-navigator@localhost',
            to: recipients.join(','), // Envoyer à tous les destinataires
            subject: `Rapport CVE - ${date}`,
            html: htmlContent
        };
        
        // Envoyer l'email
        const info = await transporter.sendMail(mailOptions);
        
        // Marquer les CVE comme envoyées après l'envoi réussi
        for (const filterName in newCVEsToMark) {
            markCVEsAsSent(filterName, newCVEsToMark[filterName]);
        }
        
        const totalNewCVEs = Object.values(newCVEsToMark).reduce((sum, ids) => sum + ids.length, 0);
        
        console.log(`Email envoyé avec succès à ${recipients.join(', ')}`);
        console.log(`Message ID: ${info.messageId}`);
        console.log(`${totalNewCVEs} nouvelle(s) CVE marquée(s) comme envoyée(s)`);
        
        return { 
            success: true, 
            message: `Email envoyé avec succès à ${recipients.join(', ')}`,
            messageId: info.messageId,
            newCVEsCount: totalNewCVEs,
            recipients: recipients
        };
    } catch (error) {
        console.error('Erreur lors de l\'envoi de l\'email:', error);
        return { 
            success: false, 
            message: `Erreur lors de l'envoi de l'email: ${error.message}` 
        };
    }
}

/**
 * Gère les requêtes API REST
 */
function handleAPI(req, res, parsedUrl) {
    const pathname = parsedUrl.pathname;
    const query = parsedUrl.query;
    
    console.log(`[API] ${req.method} ${pathname}`);
    
    // GET /api/predefined-filters - Récupérer les filtres prédéfinis
    if (pathname === '/api/predefined-filters' && req.method === 'GET') {
        try {
            if (fs.existsSync(PREDEFINED_FILTERS_FILE)) {
                const content = fs.readFileSync(PREDEFINED_FILTERS_FILE, 'utf8');
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(content);
            } else {
                // Créer le fichier avec les valeurs par défaut
                const defaultFilters = { filters: ['Dell', 'vCenter', 'ESXi'] };
                fs.writeFileSync(PREDEFINED_FILTERS_FILE, JSON.stringify(defaultFilters, null, 2), 'utf8');
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(defaultFilters));
            }
        } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: error.message }));
        }
        return;
    }
    
    // POST /api/predefined-filters - Sauvegarder les filtres prédéfinis
    if (pathname === '/api/predefined-filters' && req.method === 'POST') {
        console.log('POST /api/predefined-filters reçu');
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            console.log('Body reçu:', body);
            try {
                if (!body) {
                    throw new Error('Body vide');
                }
                
                const data = JSON.parse(body);
                
                // Valider la structure
                if (!data || !Array.isArray(data.filters)) {
                    throw new Error('Format invalide: data.filters doit être un tableau');
                }
                
                // Créer le dossier data s'il n'existe pas
                const dataDir = path.dirname(PREDEFINED_FILTERS_FILE);
                if (!fs.existsSync(dataDir)) {
                    fs.mkdirSync(dataDir, { recursive: true });
                }
                
                // Sauvegarder le fichier
                fs.writeFileSync(PREDEFINED_FILTERS_FILE, JSON.stringify(data, null, 2), 'utf8');
                console.log(`Filtres prédéfinis sauvegardés: ${data.filters.length} filtres`);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (error) {
                console.error('Erreur lors de la sauvegarde des filtres prédéfinis:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        req.on('error', (error) => {
            console.error('Erreur lors de la lecture de la requête:', error);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Erreur lors de la lecture de la requête' }));
        });
        return;
    }
    
    // GET /api/email-recipients - Récupérer la liste des destinataires
    if (pathname === '/api/email-recipients' && req.method === 'GET') {
        try {
            if (fs.existsSync(EMAIL_RECIPIENTS_FILE)) {
                const content = fs.readFileSync(EMAIL_RECIPIENTS_FILE, 'utf8');
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(content);
            } else {
                // Créer le fichier avec les valeurs par défaut
                const defaultRecipients = { recipients: ['nicolas.lebon@atos.net'] };
                const dataDir = path.dirname(EMAIL_RECIPIENTS_FILE);
                if (!fs.existsSync(dataDir)) {
                    fs.mkdirSync(dataDir, { recursive: true });
                }
                fs.writeFileSync(EMAIL_RECIPIENTS_FILE, JSON.stringify(defaultRecipients, null, 2), 'utf8');
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(defaultRecipients));
            }
        } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: error.message }));
        }
        return;
    }
    
    // POST /api/email-recipients - Ajouter un destinataire
    if (pathname === '/api/email-recipients' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                if (!body) {
                    throw new Error('Body vide');
                }
                
                const data = JSON.parse(body);
                
                // Valider la structure
                if (!data || !data.email || typeof data.email !== 'string') {
                    throw new Error('Format invalide: data.email doit être une chaîne de caractères');
                }
                
                const email = data.email.trim().toLowerCase();
                
                // Validation basique de l'email
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(email)) {
                    throw new Error('Format d\'email invalide');
                }
                
                // Charger les destinataires existants
                let recipientsData = { recipients: [] };
                if (fs.existsSync(EMAIL_RECIPIENTS_FILE)) {
                    const content = fs.readFileSync(EMAIL_RECIPIENTS_FILE, 'utf8');
                    recipientsData = JSON.parse(content);
                }
                
                if (!Array.isArray(recipientsData.recipients)) {
                    recipientsData.recipients = [];
                }
                
                // Vérifier si l'email existe déjà
                if (recipientsData.recipients.includes(email)) {
                    throw new Error('Cet email est déjà dans la liste des destinataires');
                }
                
                // Ajouter l'email
                recipientsData.recipients.push(email);
                
                // Créer le dossier data s'il n'existe pas
                const dataDir = path.dirname(EMAIL_RECIPIENTS_FILE);
                if (!fs.existsSync(dataDir)) {
                    fs.mkdirSync(dataDir, { recursive: true });
                }
                
                // Sauvegarder le fichier
                fs.writeFileSync(EMAIL_RECIPIENTS_FILE, JSON.stringify(recipientsData, null, 2), 'utf8');
                console.log(`Destinataire ajouté: ${email}`);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, recipients: recipientsData.recipients }));
            } catch (error) {
                console.error('Erreur lors de l\'ajout du destinataire:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        req.on('error', (error) => {
            console.error('Erreur lors de la lecture de la requête:', error);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Erreur lors de la lecture de la requête' }));
        });
        return;
    }
    
    // DELETE /api/email-recipients - Supprimer un destinataire
    if (pathname === '/api/email-recipients' && req.method === 'DELETE') {
        try {
            const email = query.email;
            
            if (!email) {
                throw new Error('Paramètre email requis');
            }
            
            // Charger les destinataires existants
            if (!fs.existsSync(EMAIL_RECIPIENTS_FILE)) {
                throw new Error('Aucun destinataire trouvé');
            }
            
            const content = fs.readFileSync(EMAIL_RECIPIENTS_FILE, 'utf8');
            const recipientsData = JSON.parse(content);
            
            if (!Array.isArray(recipientsData.recipients)) {
                throw new Error('Format de fichier invalide');
            }
            
            // Trouver et supprimer l'email
            const index = recipientsData.recipients.indexOf(email);
            if (index === -1) {
                throw new Error('Email non trouvé dans la liste des destinataires');
            }
            
            recipientsData.recipients.splice(index, 1);
            
            // Sauvegarder le fichier
            fs.writeFileSync(EMAIL_RECIPIENTS_FILE, JSON.stringify(recipientsData, null, 2), 'utf8');
            console.log(`Destinataire supprimé: ${email}`);
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, recipients: recipientsData.recipients }));
        } catch (error) {
            console.error('Erreur lors de la suppression du destinataire:', error);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: error.message }));
        }
        return;
    }
    
    // POST /api/send-cve-email - Envoyer l'email avec les CVE
    if (pathname === '/api/send-cve-email' && req.method === 'POST') {
        if (!db) {
            res.writeHead(503, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Base de données non disponible' }));
            return;
        }
        
        sendCVEEmail().then(result => {
            res.writeHead(result.success ? 200 : 500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
        }).catch(error => {
            console.error('Erreur lors de l\'envoi de l\'email:', error);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ 
                success: false, 
                message: `Erreur lors de l'envoi de l'email: ${error.message}` 
            }));
        });
        return;
    }
    
    // Les endpoints suivants nécessitent la base de données
    if (!db) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Base de données non disponible' }));
        return;
    }
    
    // GET /api/cves/count - Nombre total de CVE
    if (pathname === '/api/cves/count') {
        try {
            const count = db.prepare('SELECT COUNT(*) as count FROM cves').get();
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ count: count.count }));
        } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: error.message }));
        }
        return;
    }
    
    // GET /api/cves/:cveId - Un CVE spécifique
    const cveIdMatch = pathname.match(/^\/api\/cves\/(CVE-2025-\d+)$/);
    if (cveIdMatch) {
        try {
            const cveId = cveIdMatch[1];
            const stmt = db.prepare('SELECT jsonData FROM cves WHERE cveId = ?');
            const result = stmt.get(cveId);
            
            if (result) {
                const cve = JSON.parse(result.jsonData);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(cve));
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'CVE not found' }));
            }
        } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: error.message }));
        }
        return;
    }
    
    // GET /api/cves/batch - Charger plusieurs CVE par IDs
    if (pathname === '/api/cves/batch') {
        try {
            const idsParam = query.ids;
            if (!idsParam) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Parameter "ids" required (comma-separated)' }));
                return;
            }
            
            const ids = idsParam.split(',').map(id => id.trim()).filter(id => id);
            if (ids.length === 0) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'No valid CVE IDs provided' }));
                return;
            }
            
            // Limiter à 1000 CVE par requête pour éviter les problèmes de mémoire
            const limitedIds = ids.slice(0, 1000);
            const placeholders = limitedIds.map(() => '?').join(',');
            const stmt = db.prepare(`SELECT jsonData FROM cves WHERE cveId IN (${placeholders})`);
            const results = stmt.all(...limitedIds);
            
            const cves = results.map(row => JSON.parse(row.jsonData));
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ cves, count: cves.length }));
        } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: error.message }));
        }
        return;
    }
    
    // GET /api/cves - Liste paginée avec filtres optionnels
    if (pathname === '/api/cves') {
        try {
            const page = parseInt(query.page) || 1;
            const limit = Math.min(parseInt(query.limit) || 1000, 5000); // Max 5000 par page
            const offset = (page - 1) * limit;
            
            // Construire la requête avec filtres
            let whereClauses = [];
            let params = [];
            
            // Filtre par état
            if (query.state) {
                whereClauses.push('state = ?');
                params.push(query.state);
            }
            
            // Filtre par sévérité
            if (query.severity) {
                whereClauses.push('severity = ?');
                params.push(query.severity.toUpperCase());
            }
            
            // Filtre par CVSS min
            if (query.cvssMin) {
                whereClauses.push('cvssScore >= ?');
                params.push(parseFloat(query.cvssMin));
            }
            
            // Filtre par CVSS max
            if (query.cvssMax) {
                whereClauses.push('cvssScore <= ?');
                params.push(parseFloat(query.cvssMax));
            }
            
            // Recherche dans le titre, ID CVE, et produits affectés (vendor)
            if (query.search) {
                whereClauses.push('(title LIKE ? OR cveId LIKE ? OR vendor LIKE ?)');
                const searchTerm = `%${query.search}%`;
                params.push(searchTerm, searchTerm, searchTerm);
            }
            
            const whereClause = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
            
            // Tri
            let orderBy = 'datePublished DESC';
            if (query.sort === 'dateAsc') {
                orderBy = 'datePublished ASC';
            } else if (query.sort === 'cvssDesc') {
                orderBy = 'cvssScore DESC';
            } else if (query.sort === 'cvssAsc') {
                orderBy = 'cvssScore ASC';
            } else if (query.sort === 'idAsc') {
                orderBy = 'cveId ASC';
            } else if (query.sort === 'idDesc') {
                orderBy = 'cveId DESC';
            }
            
            // Compter le total
            const countStmt = db.prepare(`SELECT COUNT(*) as count FROM cves ${whereClause}`);
            const countResult = countStmt.get(...params);
            const total = countResult.count;
            
            // Récupérer les CVE
            const selectStmt = db.prepare(`
                SELECT jsonData 
                FROM cves 
                ${whereClause}
                ORDER BY ${orderBy}
                LIMIT ? OFFSET ?
            `);
            const results = selectStmt.all(...params, limit, offset);
            
            const cves = results.map(row => JSON.parse(row.jsonData));
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                cves,
                pagination: {
                    page,
                    limit,
                    total,
                    totalPages: Math.ceil(total / limit)
                }
            }));
        } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: error.message }));
        }
        return;
    }
    
    // Route API non trouvée
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'API endpoint not found' }));
}

/**
 * Crée et démarre le serveur HTTP
 */
function startServer() {
    // Ouvrir la base de données SQLite
    console.log('=== Serveur CVE Navigator ===\n');
    openDatabase();
    
    // Générer l'index au démarrage (pour compatibilité)
    generateIndex();
    
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url, true);
        let pathname = parsedUrl.pathname;
        
        // CORS headers
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        
        if (req.method === 'OPTIONS') {
            res.writeHead(200);
            res.end();
            return;
        }
        
        // Routes API REST
        if (pathname.startsWith('/api/')) {
            handleAPI(req, res, parsedUrl);
            return;
        }
        
        // Route pour régénérer l'index à la demande
        if (pathname === '/regenerate-index' && req.method === 'POST') {
            console.log('Régénération de l\'index demandée...');
            const success = generateIndex();
            res.writeHead(success ? 200 : 500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success, message: success ? 'Index régénéré avec succès' : 'Erreur lors de la régénération' }));
            return;
        }
        
        // Route racine -> index.html
        if (pathname === '/') {
            pathname = '/index.html';
        }
        
        // Servir le fichier
        serveFile(pathname, res);
    });
    
    server.listen(PORT, () => {
        console.log(`Serveur démarré sur http://localhost:${PORT}`);
        console.log(`Servez l'application à: http://localhost:${PORT}`);
        if (db) {
            console.log(`API SQLite disponible sur http://localhost:${PORT}/api/cves\n`);
        } else {
            console.log(`⚠ Mode dégradé: API SQLite non disponible (utilisez npm run import)\n`);
        }
    });
    
    // Régénérer l'index toutes les heures (pour compatibilité)
    setInterval(() => {
        console.log('Mise à jour automatique de l\'index...');
        generateIndex();
    }, 3600000); // 1 heure
    
    // Envoyer l'email automatiquement selon l'intervalle configuré
    if (db) {
        const emailIntervalHours = EMAIL_INTERVAL / (60 * 60 * 1000);
        console.log(`Envoi automatique d'email configuré toutes les ${emailIntervalHours} heures`);
        
        setInterval(async () => {
            console.log('Envoi automatique de l\'email CVE...');
            const result = await sendCVEEmail();
            if (result.success) {
                console.log('✓ Email envoyé automatiquement avec succès');
            } else {
                console.error('✗ Erreur lors de l\'envoi automatique:', result.message);
            }
        }, EMAIL_INTERVAL);
    } else {
        console.log('⚠ Envoi automatique d\'email désactivé (base de données non disponible)');
    }
    
    // Fermer la base de données proprement à l'arrêt
    process.on('SIGINT', () => {
        console.log('\nArrêt du serveur...');
        if (db) {
            db.close();
        }
        process.exit(0);
    });
}

// Démarrer le serveur
startServer();

