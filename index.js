const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const ejs = require('ejs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const settings = require('./settings.json');
const Docker = require('dockerode');
const docker = new Docker();
const { exec } = require('child_process');
const { performance } = require('perf_hooks');

const DB_PATH = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(DB_PATH);

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    email TEXT,
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

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
var expressWs = require('express-ws')(app);

app.use(session({
    secret: 'geheimnis',
    resave: false,
    saveUninitialized: true
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

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
                        res.render('dashboard.ejs', {
                            settings: settings,
                            currency: settings.currency,
                            userId: req.session.userId,
                            username: row.username,
                            email: row.email,
                            servers: servers,
                            balance: balance,
                            role: role
                        });
                    }
                });
            }
        });
    } else {
        res.redirect('/login');
    }
});

app.get('/freeserver', async (req, res) => {
    const serverName = 'free_minecraft_server_' + generateRandomString(8); 
    const ramMb = 1024; 
    const diskMb = 1024; 
    const vCores = 2; 
    const pricePerMonth = 0; 
    const expiryTimestamp = Date.now() + 30 * 24 * 60 * 60 * 1000; 
    const ownerId = req.session.userId;

    try {
        const containerId = await createMinecraftServerContainer(serverName, ownerId, ramMb, diskMb, vCores);

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



async function startContainer(containerId) {
    const container = docker.getContainer(containerId);
    await container.start();
}

async function stopContainer(containerId) {
    const container = docker.getContainer(containerId);
    await container.stop();
}

app.post('/start/:serverId', (req, res) => {
    const serverId = req.params.serverId;
    db.get(`SELECT * FROM servers WHERE id = ?`, [serverId], async (err, server) => {
        if (err) {
            console.error('Fehler beim Abrufen von Serverinformationen aus der Datenbank:', err);
            res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else {
            if (req.session.userId === server.owner_id) {
                try {
                    await startContainer(server.container_id);
                    res.redirect('/dashboard');
                } catch (error) {
                    console.error('Fehler beim Starten des Containers:', error);
                    res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                }
            } else {
                res.redirect('/dashboard');
            }
        }
    });
});

app.post('/stop/:serverId', (req, res) => {
    const serverId = req.params.serverId;
    db.get(`SELECT * FROM servers WHERE id = ?`, [serverId], async (err, server) => {
        if (err) {
            console.error('Fehler beim Abrufen von Serverinformationen aus der Datenbank:', err);
            res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else {
            if (req.session.userId === server.owner_id) {
                try {
                    await stopContainer(server.container_id);
                    res.redirect('/dashboard');
                } catch (error) {
                    console.error('Fehler beim Stoppen des Containers:', error);
                    res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                }
            } else {
                res.redirect('/dashboard');
            }
        }
    });
});

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

async function createMinecraftServerContainer(serverName, ownerId, ramMb, diskMb, vCores) {
    return new Promise((resolve, reject) => {
        const memoryLimit = `${ramMb}M`;
        const cpuShares = vCores * 1024; 
        console.log(vCores)
        exec(`docker run -d --name ${serverName} --memory=${memoryLimit} --cpu-shares=${cpuShares} --cpuset-cpus="0-${vCores - 1}" -e EULA=true -e DISK=${diskMb}G itzg/minecraft-server`, (error, stdout, stderr) => {
            if (error) {
                reject(error);
                return;
            }
            const containerId = stdout.trim(); 
            resolve(containerId);
        });
    });
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

app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [username, email], (err, row) => {
        if (err) {
            console.error('Fehler beim Überprüfen der Benutzerdaten:', err);
            res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else if (row) {
            res.send('Benutzername oder E-Mail-Adresse bereits registriert.');
        } else {
            db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, [username, email, password], function (err) {
                if (err) {
                    console.error('Fehler beim Hinzufügen des Benutzers zur Datenbank:', err);
                    res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                } else {
                    const userId = this.lastID;
                    req.session.userId = userId;
                    const defaultRole = 3;
                    db.run(`UPDATE users SET role = ? WHERE id = ?`, [defaultRole, userId], (err) => {
                        if (err) {
                            console.error('Fehler beim Festlegen der Standardrolle für den Benutzer:', err);
                            res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
                        } else {
                            res.redirect('/dashboard');
                        }
                    });
                }
            });
        }
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password], (err, row) => {
        if (err) {
            console.error('Fehler beim Überprüfen der Anmeldeinformationen:', err);
            res.send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
        } else if (!row) {
            res.send('Falscher Benutzername oder Passwort');
        } else {
            req.session.userId = row.id;
            res.redirect('/dashboard');
        }
    });
});

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

app.post('/servercommand/:containerId', isContainerOwner, (req, res) => {
    const containerId = req.params.containerId;
    const command = req.body.command;
console.log(command)
    docker.getContainer(containerId).inspect((err, data) => {
        if (err || !data.State.Running) {
            res.status(400).send('Der Container ist nicht gestartet oder existiert nicht.');
        } else {
            const dockerCommand = spawn('docker', ['exec', '-i', containerId, 'bash', '-c', command]);
            let output = '';

            dockerCommand.stdout.on('data', (data) => {
                output += data.toString();
            });

            dockerCommand.stderr.on('data', (data) => {
                console.error(`Fehler beim Ausführen des Befehls: ${data}`);
                output += data.toString();
            });

            dockerCommand.on('close', (code) => {
                console.log(`Befehl ausgeführt mit Exit-Code ${code}`);
                res.send(output); 
            });
        }
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

async function checkAndPullMinecraftImage() {
    return new Promise((resolve, reject) => {
        exec('docker pull itzg/minecraft-server', (error, stdout, stderr) => {
            if (error) {
                reject(error);
                return;
            }
            console.log('Minecraft-Image wurde überprüft und falls erforderlich heruntergeladen.');
            resolve();
        });
    });
}

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

let minecraftImageChecked = false;

app.use(async (req, res, next) => {
    try {
        if (!minecraftImageChecked) {
            await checkAndPullMinecraftImage();
            minecraftImageChecked = true;
        }
        next();
    } catch (error) {
        console.error('Fehler beim Überprüfen und Herunterladen des Minecraft-Images:', error);
        res.status(500).send('Ein Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.');
    }
});

app.ws('/serverconsole/:containerId', (ws, req) => {
    const containerId = req.params.containerId;
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



app.listen(3000, () => {
    console.log('Server läuft auf http://localhost:3000');
});