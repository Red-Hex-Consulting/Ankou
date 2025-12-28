use std::env;

fn main() {
    // Generate random XOR key if not provided
    let xor_key = match env::var("PHANTASM_XOR_KEY") {
        Ok(key) if !key.is_empty() => {
            println!("cargo:warning=Using provided XOR key: {}", key);
            key
        }
        _ => {
            // Generate random byte as hex
            let random_byte = (std::process::id() ^ std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u32) as u8;
            let key = format!("{:02X}", random_byte);
            println!("cargo:warning=Generated random XOR key: {}", key);
            key
        }
    };

    // Set the XOR key for compilation
    println!("cargo:rustc-env=PHANTASM_XOR_KEY={}", xor_key);
    
    // Rerun if the environment variable changes
    println!("cargo:rerun-if-env-changed=PHANTASM_XOR_KEY");
}




