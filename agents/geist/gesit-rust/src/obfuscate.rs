// String obfuscation using compile-time XOR encryption
// This prevents static strings from appearing in the binary

/// Deobfuscate bytes at runtime
#[inline(always)]
#[allow(dead_code)]
pub fn deobfuscate(input: &[u8]) -> String {
    const XOR_KEY: u8 = 0x7A;
    let decoded: Vec<u8> = input.iter().map(|b| b ^ XOR_KEY).collect();
    String::from_utf8_lossy(&decoded).to_string()
}

/// Macro to obfuscate a string literal at compile time
/// Usage: obfstr!("my secret string")
#[macro_export]
macro_rules! obfstr {
    ($s:literal) => {{
        const INPUT: &[u8] = $s.as_bytes();
        const LEN: usize = INPUT.len();
        const XOR_KEY: u8 = 0x7A;
        
        const ENCRYPTED: [u8; LEN] = {
            let mut result = [0u8; LEN];
            let mut i = 0;
            while i < LEN {
                result[i] = INPUT[i] ^ XOR_KEY;
                i += 1;
            }
            result
        };
        
        $crate::obfuscate::deobfuscate(&ENCRYPTED)
    }};
}

// Example usage:
// let host = obfstr!("localhost");
// let port = obfstr!("8081");

