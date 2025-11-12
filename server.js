/**
 * Serveur HTTP avec génération automatique de l'index CVE et API SQLite
 * Usage: node server.js [port]
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const Database = require('better-sqlite3');

const PORT = process.argv[2] || 8080;
const CVES_DIR = path.join(__dirname, 'cves', '2025');
const INDEX_FILE = path.join(__dirname, 'cves', '2025', 'index.json');
const DB_PATH = path.join(__dirname, 'cves.db');

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
 * Gère les requêtes API REST
 */
function handleAPI(req, res, parsedUrl) {
    const pathname = parsedUrl.pathname;
    const query = parsedUrl.query;
    
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
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
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

