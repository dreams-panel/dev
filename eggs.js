const util = require('util');
const fs = require('fs');
const { exec } = require('child_process');

const readdir = util.promisify(fs.readdir);
const readFile = util.promisify(fs.readFile);
const eggs = fs.readdirSync('./eggs');

const eggFunctions = [];

async function loadEggFunctions() {
    try {
        const files = await readdir('./eggs');
        console.log('Loading eggs...');
        console.log('Found ' + files.length + ' eggs');
        console.log(files);

        for (const file of files) {
            if (file.endsWith('.json')) {
                const eggName = file.substring(0, file.length - 5);
                const filePath = `./eggs/${file}`;

                const content = await readFile(filePath, 'utf8');
                const { name, image, run } = JSON.parse(content);

                const createServerFunction = async function(serverName, ownerId, ramMb, diskMb, vCores, port) {
                    const cpuCoreRange = `0-${vCores - 1}`;
                    const runCommand = run
                        .replace('${serverName}', serverName)
                        .replace('${ownerId}', ownerId)
                        .replace('${ramMb}', ramMb)
                        .replace('${diskMb}', diskMb)
                        .replace('${vCores}', vCores)
                        .replace('${port}', port)
                        // cpuset-cpus-Zeichenfolge ersetzen
                        .replace(/\$\{cpuCoreRange\}/g, cpuCoreRange)
                        .replace('${memoryLimit}', `${ramMb}M`)
                        .replace('${cpuShares}', `${vCores * 1024}`);

                    return new Promise((resolve, reject) => {
                        exec(runCommand, (error, stdout, stderr) => {
                            if (error) {
                                reject(error);
                                return;
                            }
                            const containerId = stdout.trim();
                            resolve(containerId);
                        });
                    });
                };

                eggFunctions.push({
                    eggName: eggName,
                    createServerContainer: createServerFunction
                });
            }
        }
        console.log('Done creating egg functions!');
    } catch (error) {
        console.error('Error:', error);
    }
}


const jsonData = {};

// Ein Array mit den Verzeichnissen, die du durchsuchen möchtest
const directories = ['./eggs'];

// Durchlaufe jedes Verzeichnis
directories.forEach(directory => {
    // Lies die Dateien im aktuellen Verzeichnis
    const files = fs.readdirSync(directory);
    
    // Erstelle ein Unterojekt für das aktuelle Verzeichnis
    const directoryName = directory.split('/').pop();
    jsonData[`${directoryName}-json`] = {};

    // Durchlaufe jede Datei im aktuellen Verzeichnis
    files.forEach(file => {
        // Lies den Inhalt der Datei
        const content = fs.readFileSync(`${directory}/${file}`, 'utf8');
        
        // Parst den JSON-Inhalt der Datei
        const parsedContent = JSON.parse(content);

        // Füge die Datei als Unterkategorie mit dem Dateinamen, dem Inhalt und dem Namen hinzu
        jsonData[`${directoryName}-json`][file] = { content: parsedContent };

        // Füge auch den Namen der Datei als separates Attribut hinzu
        jsonData[`${directoryName}-json`][file].name = parsedContent.name;
        jsonData[`${directoryName}-json`][file].description = parsedContent.description;
    });
});

module.exports = { eggFunctions, loadEggFunctions, jsonData };

