const XOR_KEY: u8 = 0x7A;

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

