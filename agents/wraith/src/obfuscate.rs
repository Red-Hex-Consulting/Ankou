const fn parse_hex_key() -> u8 {
    match option_env!("WRAITH_XOR_KEY") {
        Some(hex_str) => {
            let bytes = hex_str.as_bytes();
            if bytes.len() >= 2 {
                let high = match bytes[0] {
                    b'0'..=b'9' => bytes[0] - b'0',
                    b'a'..=b'f' => bytes[0] - b'a' + 10,
                    b'A'..=b'F' => bytes[0] - b'A' + 10,
                    _ => 7,
                };
                let low = match bytes[1] {
                    b'0'..=b'9' => bytes[1] - b'0',
                    b'a'..=b'f' => bytes[1] - b'a' + 10,
                    b'A'..=b'F' => bytes[1] - b'A' + 10,
                    _ => 10,
                };
                (high << 4) | low
            } else {
                0x7A
            }
        }
        None => 0x7A,
    }
}

const XOR_KEY: u8 = parse_hex_key();

#[inline(always)]
pub fn deobfuscate(input: &[u8]) -> String {
    let decoded: Vec<u8> = input.iter().map(|b| b ^ XOR_KEY).collect();
    String::from_utf8_lossy(&decoded).to_string()
}

#[macro_export]
macro_rules! obfstr {
    ($s:literal) => {{
        const INPUT: &[u8] = $s.as_bytes();
        const LEN: usize = INPUT.len();
        const XOR_KEY: u8 = match option_env!("WRAITH_XOR_KEY") {
            Some(hex_str) => {
                let bytes = hex_str.as_bytes();
                if bytes.len() >= 2 {
                    let high = match bytes[0] {
                        b'0'..=b'9' => bytes[0] - b'0',
                        b'a'..=b'f' => bytes[0] - b'a' + 10,
                        b'A'..=b'F' => bytes[0] - b'A' + 10,
                        _ => 7,
                    };
                    let low = match bytes[1] {
                        b'0'..=b'9' => bytes[1] - b'0',
                        b'a'..=b'f' => bytes[1] - b'a' + 10,
                        b'A'..=b'F' => bytes[1] - b'A' + 10,
                        _ => 10,
                    };
                    (high << 4) | low
                } else {
                    0x7A
                }
            }
            None => 0x7A,
        };
        
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

