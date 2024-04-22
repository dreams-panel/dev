const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const ejs = require('ejs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const settings = require('./settings.json');
const Docker = require('dockerode');
const docker = new Docker();
const fs = require('fs');
const { exec } = require('child_process');
const { eggFunctions, loadEggFunctions, jsonData } = require('./eggs');
const { spawn } = require('child_process');

loadEggFunctions();

const DB_PATH = path.join(__dirname, 'database.db');

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Fehler beim Öffnen der SQLite-Datenbank:', err);
    } else {
        console.log('SQLite-Datenbank geöffnet oder erstellt.');
        createTables();
    }
});

function createTables() {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        email TEXT,
        language TEXT,
        last_login_timestamp INTEGER,
        balance REAL DEFAULT 0,
        role INTEGER DEFAULT 3
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        owner_id INTEGER,
        ram_mb INTEGER,
        disk_mb INTEGER,
        vcores INTEGER,
        price_per_month REAL,
        expiry_timestamp INTEGER,
        container_id TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        sess TEXT,
        expire INTEGER
    )`);

    console.log('Tabellen erstellt oder bereits vorhanden.');
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
var expressWs = require('express-ws')(app);

app.use(session({
    secret: 'geheimnis',
    resave: false,
    saveUninitialized: true,
    store: new SQLiteStore({
        db: 'database.db',
        table: 'sessions',
        dir: __dirname,
        ttl: 3600
    })
}));


app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

const row = {

}

app.get('/', (req, res) => {
    res.render('index.ejs');
});

app.get('/login', (req, res) => {
    if (!req.session.userId) {
        res.render('login.ejs');
    } else {
        res.redirect('/dashboard');
    }
});

app.get('/register', (req, res) => {
    if (!req.session.userId) {
        res.render('register.ejs');
    } else {
        res.redirect('/dashboard');
    }
});

app.get('/dashboard', (req, res) => {
    if (req.session && req.session.userId) {
        db.get(`SELECT * FROM users WHERE id = ?`, [req.session.userId], (err, row) => {
            if (err) {
                console.error('Fehler beim Abrufen von Benutzerinformationen aus der Datenbank:', err);
                res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
            } else {
                db.all(`SELECT * FROM servers WHERE owner_id = ?`, [req.session.userId], (err, servers) => {
                    if (err) {
                        console.error('Fehler beim Abrufen der Serverliste aus der Datenbank:', err);
                        res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                    } else {
                        const balance = row.balance;
                        const role = row.role;

                        // Sprachdatei basierend auf der vom Benutzer ausgewählten Sprache laden
                        const langFilePath = path.join(__dirname, 'languages', row.language, 'lang.json');
                        let langData;
                        try {
                            langData = require(langFilePath);
                        } catch (error) {
                            console.error('Fehler beim Laden der Sprachdatei:', error);
                            // Verwende eine Standard-Sprachdatei, falls die gewünschte Sprache nicht gefunden wurde
                            langData = require(path.join(__dirname, 'languages', 'en', 'lang.json'));
                        }

                        res.render('dashboard.ejs', {
                            settings: settings,
                            currency: settings.currency,
                            userId: req.session.userId,
                            username: row.username,
                            email: row.email,
                            servers: servers,
                            balance: balance,
                            role: role,
                            lang: langData
                        });
                    }
                });
            }
        });
    } else {
        res.redirect('/login');
    }
});

app.get('/admin', isAdmin, (req, res) => {
        res.render('admin/admin.ejs', {
            settings: settings,
            currency: settings.currency,
            userId: req.session.userId,
            username: req.session.username,
            email: req.session.email,
            jsonData: jsonData
        } );
})



async function getAvailablePort(startPort, endPort) {
    return new Promise((resolve, reject) => {
        exec(`docker ps -a --format "{{.Names}}\t{{.Ports}}"`, (error, stdout, stderr) => {
            if (error) {
                reject(error);
                return;
            }

            const lines = stdout.trim().split('\n');
            const usedPorts = lines.flatMap(line => line.match(/(\d+)-(\d+):(\d+)/g) || []);
            const availablePorts = Array.from({ length: endPort - startPort + 1 }, (_, i) => startPort + i)
                .filter(port => !usedPorts.some(usedPort => usedPort.includes(`:${port}->`)));

            if (availablePorts.length > 0) {
                resolve(availablePorts[0]);
            } else {
                reject(new Error('Kein verfügbarer Port gefunden.'));
            }
        });
    });
}


// Handler für die Route /freeserver
app.get('/freeserver', async (req, res) => {
    const serverName = 'free_minecraft_server_' + generateRandomString(8);
    const ramMb = 2024;
    const diskMb = 4024;
    const vCores = 4;
    const pricePerMonth = 0;
    const expiryTimestamp = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 Tage Ablaufzeit
    const ownerId = req.session.userId;

    try {
        // Überprüfen, ob die Funktion createServerContainer für Minecraft vorhanden ist
        const minecraftFunction = eggFunctions.find(egg => egg.eggName === 'minecraft');

        if (minecraftFunction && minecraftFunction.createServerContainer) {
            // Dynamisch den verfügbaren Port ermitteln
            const startingPort = 25565;
            const endPort = 65535;
            const port = await getAvailablePort(startingPort, endPort);

            // Erstellen des Servers mit der dynamisch erstellten Funktion
            const containerId = await minecraftFunction.createServerContainer(serverName, ownerId, ramMb, diskMb, vCores, port);

            // Füge den Server zur Datenbank hinzu
            db.run(`INSERT INTO servers (name, owner_id, ram_mb, disk_mb, vcores, price_per_month, expiry_timestamp, container_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [serverName, ownerId, ramMb, diskMb, vCores, pricePerMonth, expiryTimestamp, containerId],
                (err) => {
                    if (err) {
                        console.error('Fehler beim Hinzufügen des kostenlosen Servers zur Datenbank:', err);
                        res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                    } else {
                        res.send('Ein kostenloser Minecraft-Server für 30 Tage wurde erfolgreich erstellt und in der Datenbank eingetragen.');
                    }
                }
            );
        } else {
            console.error('Funktion createServerContainer für Minecraft nicht gefunden.');
            res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        }
    } catch (error) {
        console.error('Fehler beim Erstellen des Minecraft-Servers:', error);
        res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
    }
});



function isContainerOwner(req, res, next) {
    const serverId = req.params.serverId;
    const containerId = req.params.containerId;
    const userId = req.session.userId;

    const queryParam = serverId ? serverId : containerId;

    const query = serverId ? `SELECT * FROM servers WHERE id = ?` : `SELECT * FROM servers WHERE container_id = ?`;

    db.get(query, [queryParam], (err, server) => {
        if (err) {
            console.error('Fehler beim Abrufen von Serverinformationen aus der Datenbank:', err);
            res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else if (!server) {
            res.status(404).send('Server nicht gefunden.');
        } else {
            if (userId === server.owner_id) {
                next();
            } else {
                res.redirect('/dashboard');
            }
        }
    });
}










function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}





app.ws('/api/resources', (ws, req) => {
    const interval = setInterval(async () => {
        try {
            const containers = await docker.listContainers({ all: true });
            const resources = {};

            for (const containerInfo of containers) {
                const container = docker.getContainer(containerInfo.Id);
                const stats = await new Promise((resolve, reject) => {
                    container.stats((err, stream) => {
                        if (err) {
                            console.error('Fehler beim Abrufen der Container-Statistiken:', err);
                            reject(err);
                        }
                        let data = '';
                        stream.on('data', chunk => {
                            data += chunk;
                        });
                        stream.on('end', () => {
                            resolve(data);
                        });
                    });
                });

                const statsObj = JSON.parse(stats);

                resources[containerInfo.Id] = {
                    ramUsage: statsObj.memory_stats.usage / (1024 * 1024),
                    ramLimit: statsObj.memory_stats.limit / (1024 * 1024),
                    cpuUsage: statsObj.cpu_stats.cpu_usage.total_usage / statsObj.cpu_stats.system_cpu_usage * 100,
                    cpuLimit: statsObj.cpu_stats.cpu_quota / statsObj.cpu_stats.cpu_period * 100,
                    diskUsage: statsObj.diskio_stats.weighted_io_service_bytes / (1024 * 1024),
                    diskLimit: 1024 
                };
            }

            ws.send(JSON.stringify(resources));
        } catch (error) {
            console.error('Fehler beim Überwachen der Ressourcen:', error);
        }
    }, 5000);

    ws.on('close', () => {
        clearInterval(interval);
    });
});

const bcrypt = require('bcrypt');

app.post('/register', (req, res) => {
    const { username, email, password, language } = req.body;
    // Überprüfe, ob eine Sprache ausgewählt wurde, wenn nicht, setze standardmäßig 'en'
    const selectedLanguage = language || 'en';

    // Generiere ein Salt und verschlüssele das Passwort
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Fehler beim Hashen des Passworts:', err);
            return res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        }

        db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [username, email], (err, row) => {
            if (err) {
                console.error('Fehler beim Überprüfen der Benutzerdaten:', err);
                return res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
            } 
            if (row) {
                return res.send('Benutzername oder E-Mail-Adresse bereits registriert.');
            } 
            
            // Füge den Benutzer zur Datenbank hinzu
            db.run(`INSERT INTO users (username, email, password, language) VALUES (?, ?, ?, ?)`, [username, email, hashedPassword, selectedLanguage], function (err) {
                if (err) {
                    console.error('Fehler beim Hinzufügen des Benutzers zur Datenbank:', err);
                    return res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                } 
                
                const userId = this.lastID;
                req.session.userId = userId;
                const defaultRole = 3;
                
                // Setze die Standardrolle für den Benutzer
                db.run(`UPDATE users SET role = ? WHERE id = ?`, [defaultRole, userId], (err) => {
                    if (err) {
                        console.error('Fehler beim Festlegen der Standardrolle für den Benutzer:', err);
                        return res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                    } 
                    res.redirect('/dashboard');
                });
            });
        });
    });
});




app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
        if (err) {
            console.error('Fehler beim Überprüfen der Anmeldeinformationen:', err);
            return res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } 
        if (!row) {
            return res.send('Falscher Benutzername oder Passwort');
        }
        // Vergleiche das eingegebene Passwort mit dem verschlüsselten Passwort aus der Datenbank
        bcrypt.compare(password, row.password, (bcryptErr, result) => {
            if (bcryptErr) {
                console.error('Fehler beim Vergleichen der Passwörter:', bcryptErr);
                return res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.');
            }
            if (!result) {
                return res.send('Falscher Benutzername oder Passwort');
            }
            req.session.userId = row.id;
            db.run(`UPDATE users SET last_login_timestamp = DATETIME('now') WHERE id = ?`, [row.id], (updateErr) => {
                if (updateErr) {
                    console.error('Fehler beim Aktualisieren der Anmeldezeit:', updateErr);
                    return res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.');
                }
                res.redirect('/dashboard');
            });
        });
    });
});



app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
})

app.get('/servers', (req, res) => {
    db.all(`SELECT * FROM servers`, (err, rows) => {
        if (err) {
            console.error('Fehler beim Abrufen der Serverliste aus der Datenbank:', err);
            res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else {
            res.render('servers.ejs', { servers: rows });
        }
    });
});

app.get('/server/:serverId', (req, res) => {
    const serverId = req.params.serverId;
    db.get(`SELECT * FROM servers WHERE id = ?`, [serverId], (err, row) => {
        if (err) {
            console.error('Fehler beim Abrufen der Serverdaten aus der Datenbank:', err);
            res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else if (!row) {
            res.send('Server nicht gefunden.');
        } else {
            if (req.session.userId === row.owner_id) {

                const resources = { ramUsage: row.ramUsage, ramLimit: row.ramLimit, cpuUsage: row.cpuUsage, cpuLimit: row.cpuLimit, diskUsage: row.diskUsage, diskLimit: row.diskLimit };
                res.render('manage_server.ejs', { server: row, resources: resources });
            } else {
                res.redirect('/dashboard');
            }
        }
    });
});

app.put('/renamefile/:serverId', isContainerOwner, (req, res) => {
    const serverId = req.params.serverId;
    const { currentPath, newName } = req.body;

    const containerId = getContainerIdForServer(serverId); // Implementieren Sie eine Funktion, um die Container-ID basierend auf der Server-ID zu erhalten
    const command = `docker exec ${containerId} mv ${currentPath} ${newName}`;

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`Fehler beim Umbenennen der Datei/Verzeichnisses: ${error.message}`);
            res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
            return;
        }
        if (stderr) {
            console.error(`Fehler beim Umbenennen der Datei/Verzeichnisses: ${stderr}`);
            res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
            return;
        }
        console.log(`Datei/Verzeichnis erfolgreich umbenannt: ${stdout}`);
        res.status(200).send('Datei/Verzeichnis erfolgreich umbenannt.');
    });
});

function stopAndRemoveContainer(containerId) {
    return new Promise((resolve, reject) => {
        exec(`docker stop ${containerId} && docker rm ${containerId}`, (error, stdout, stderr) => {
            if (error) {
                reject(error);
                return;
            }
            resolve(stdout.trim());
        });
    });
}

app.post('/delete/:serverId', async (req, res) => {
    const serverId = req.params.serverId;
    db.get(`SELECT * FROM servers WHERE id = ?`, [serverId], async (err, server) => {
        if (err) {
            console.error('Fehler beim Abrufen von Serverinformationen aus der Datenbank:', err);
            res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else {
            if (req.session.userId === server.owner_id) {
                try {
                    await stopAndRemoveContainer(server.container_id);
                    db.run(`DELETE FROM servers WHERE id = ?`, [serverId], (err) => {
                        if (err) {
                            console.error('Fehler beim Löschen des Servers aus der Datenbank:', err);
                            res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                        } else {
                            res.redirect('/dashboard');
                        }
                    });
                } catch (error) {
                    console.error('Fehler beim Stoppen und Entfernen des Containers:', error);
                    res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                }
            } else {
                res.redirect('/dashboard');
            }
        }
    });
});

// Stoppen des Containers
app.post('/server/stop/:containerId', isContainerOwner, (req, res) => {
    const containerId = req.params.containerId;
    exec(`docker stop ${containerId}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Fehler beim Stoppen des Containers ${containerId}: ${error}`);
            return res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.');
        }
        if (stderr) {
            console.error(`Fehler beim Stoppen des Containers ${containerId}: ${stderr}`);
            return res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.');
        }
        console.log(`Container ${containerId} erfolgreich gestoppt.`);
        res.status(200).send('Container erfolgreich gestoppt.');
    });
});

// Starten des Containers
app.post('/server/start/:containerId', isContainerOwner, (req, res) => {
    const containerId = req.params.containerId;
    exec(`docker start ${containerId}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Fehler beim Starten des Containers ${containerId}: ${error}`);
            return res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.');
        }
        if (stderr) {
            console.error(`Fehler beim Starten des Containers ${containerId}: ${stderr}`);
            return res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.');
        }
        res.status(200).send('Container erfolgreich gestartet.');
    });
});


app.post('/server/restart/:containerId', isContainerOwner, (req, res) => {
    const containerId = req.params.containerId;
    exec(`docker restart ${containerId}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Fehler beim restarten des Containers ${containerId}: ${error}`);
            return res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.');
        }
        if (stderr) {
            console.error(`Fehler beim restarten des Containers ${containerId}: ${stderr}`);
            return res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.');
        }
        res.status(200).send('Container erfolgreich gerestarten.');
    });
});

app.post('/server/kill/:containerId', isContainerOwner, (req, res) => {
    const containerId = req.params.containerId;
    exec(`docker kill ${containerId}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Fehler beim killen des Containers ${containerId}: ${error}`);
            return res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.');
        }
        if (stderr) {
            console.error(`Fehler beim killen des Containers ${containerId}: ${stderr}`);
            return res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut.');
        }
        res.status(200).send('Container erfolgreich gerestarten.');
    });
});

app.get('/serverfiles/:containerId', isContainerOwner, (req, res) => {
    const containerId = req.params.containerId;

    const command = `docker exec ${containerId} ls -al`;

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`Fehler beim Abrufen der Dateiliste im Container ${containerId}: ${error}`);
            res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
            return;
        }
        if (stderr) {
            console.error(`Fehler beim Abrufen der Dateiliste im Container ${containerId}: ${stderr}`);
            res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
            return;
        }

        const files = stdout.trim().split('\n');

        res.json({ files: files });
    });
});

app.get('/server/:serverId/files', isContainerOwner, (req, res) => {
    const serverId = req.params.serverId;

    db.get(`SELECT * FROM servers WHERE id = ?`, [serverId], (err, server) => {
        if (err) {
            console.error('Fehler beim Abrufen von Serverinformationen aus der Datenbank:', err);
            res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else if (!server) {
            res.status(404).send('Server nicht gefunden.');
        } else {
            const containerId = server.container_id;
            const command = `docker exec ${containerId} ls -al`;

            exec(command, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Fehler beim Abrufen der Dateiliste im Container ${containerId}: ${error}`);
                    res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                    return;
                }
                if (stderr) {
                    console.error(`Fehler beim Abrufen der Dateiliste im Container ${containerId}: ${stderr}`);
                    res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                    return;
                }

                const files = stdout.trim().split('\n');

                res.render('server_files.ejs', { files: files, server: server });
            });
        }
    });
});



app.post('/extend/:serverId', (req, res) => {
    const serverId = req.params.serverId;
    db.get(`SELECT * FROM servers WHERE id = ?`, [serverId], (err, server) => {
        if (err) {
            console.error('Fehler beim Abrufen von Serverinformationen aus der Datenbank:', err);
            res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else {
            if (req.session.userId === server.owner_id) {
                const priceFor30Days = server.price_per_month;
                db.get(`SELECT * FROM users WHERE id = ?`, [server.owner_id], (err, user) => {
                    if (err) {
                        console.error('Fehler beim Abrufen von Benutzerinformationen aus der Datenbank:', err);
                        res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                    } else {
                        if (user.balance >= priceFor30Days) {
                            const newBalance = user.balance - priceFor30Days;
                            db.run(`UPDATE users SET balance = ? WHERE id = ?`, [newBalance, user.id], (err) => {
                                if (err) {
                                    console.error('Fehler beim Aktualisieren des Benutzerguthabens in der Datenbank:', err);
                                    res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                                } else {
                                    const newExpiryTimestamp = server.expiry_timestamp + 30 * 24 * 60 * 60 * 1000;
                                    db.run(`UPDATE servers SET expiry_timestamp = ? WHERE id = ?`, [newExpiryTimestamp, serverId], (err) => {
                                        if (err) {
                                            console.error('Fehler beim Aktualisieren des Ablaufdatums des Servers in der Datenbank:', err);
                                            res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                                        } else {
                                            res.redirect('/dashboard');
                                        }
                                    });
                                }
                            });
                        } else {
                            res.send('Sie haben nicht genügend Guthaben, um den Server zu verlängern.');
                        }
                    }
                });
            } else {
                res.redirect('/dashboard');
            }
        }
    });
});

wss.on('connection', (ws, req) => {
    const containerId = req.url.split('/')[2]; 
    const command = `docker logs -f ${containerId}`;

    const child = exec(command);

    child.stdout.on('data', (data) => {
        ws.send(data.toString()); 
    });

    child.stderr.on('data', (data) => {
        console.error(`stderr: ${data}`);
    });

    ws.on('close', () => {

        child.kill();
    });
});



app.ws('/serverconsole/:containerId', (ws, req) => {
    const containerId = req.params.containerId;
    let buffer = ''; // Puffer für die letzten 200 Zeilen

    // Befehl zum Anzeigen der Logs des Containers
    const command = `docker logs --tail 200 -f ${containerId}`;

    const child = exec(command);

    child.stdout.on('data', (data) => {
        buffer += data.toString(); // Daten zum Puffer hinzufügen
        const lines = buffer.split('\n'); // Zeilen aufteilen
        const lastLines = lines.slice(Math.max(lines.length - 200, 0)); // Nur die letzten 200 Zeilen behalten
        ws.send(lastLines.join('\n')); // Aktualisierte Zeilen an WebSocket senden
        buffer = lastLines.join('\n'); // Puffer aktualisieren
    });

    child.stderr.on('data', (data) => {
        console.error(`stderr: ${data}`);
    });

    ws.on('close', () => {
        child.kill();
    });

    ws.on('message', (command) => {
        // Befehl vom Frontend empfangen und an den Container senden
        exec(`docker exec ${containerId} sh -c "${command}"`, (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                return;
            }
            if (stderr) {
                console.error(`stderr: ${stderr}`);
                return;
            }
            console.log(`stdout: ${stdout}`);
        });
    });
});


function checkAndDeleteExpiredServers() {
    const currentTimestamp = Date.now();
    db.all(`SELECT * FROM servers WHERE expiry_timestamp <= ?`, [currentTimestamp], async (err, servers) => {
        if (err) {
            console.error('Fehler beim Abrufen abgelaufener Server aus der Datenbank:', err);
            return;
        }
        for (const server of servers) {
            try {
                await stopAndRemoveContainer(server.container_id);
                db.run(`DELETE FROM servers WHERE id = ?`, [server.id], (err) => {
                    if (err) {
                        console.error('Fehler beim Löschen des abgelaufenen Servers aus der Datenbank:', err);
                    } else {
                        console.log(`Server ${server.id} erfolgreich gelöscht.`);
                    }
                });
            } catch (error) {
                console.error('Fehler beim Stoppen und Löschen des abgelaufenen Servers:', error);
            }
        }
    });
}

setInterval(checkAndDeleteExpiredServers, 1 * 60 * 60 * 1000);

setTimeout(checkAndDeleteExpiredServers, 20000);

function isAdmin(req, res, next) {
    const userId = req.session.userId;
    db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err) {
            console.error('Fehler beim Abrufen von Benutzerinformationen aus der Datenbank:', err);
            res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else {
            if (user.role === 1) { // Annahme: 1 steht für Admin-Rolle
                next(); // Benutzer ist ein Administrator
            } else {
                res.status(403).send('Sie haben keine Berechtigung für diese Aktion.'); // Benutzer ist kein Administrator
            }
        }
    });
}


app.listen(settings.port, () => {
    console.log('Server is running on http://localhost:3000');
});