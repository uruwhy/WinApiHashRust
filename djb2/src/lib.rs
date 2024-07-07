// Calculates DJB2 hash for given input bytes
// Reference: http://www.cse.yorku.ca/~oz/hash.html
pub fn djb2_hash(input: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for c in input.iter() {
        hash = hash.wrapping_shl(5).wrapping_add(hash).wrapping_add(*c as u32);
    }
    hash
}

// Reference: https://www.convertcase.com/hashing/djb-hash-calculator
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_shift() {
        assert_eq!(0x11111111u32.wrapping_shl(4), 0x11111110u32);
    }

    #[test]
    fn test_djb2_hash_cstr() {
        let mut cstr = CStr::from_bytes_with_nul(b"RegCreateKeyExW\0").unwrap();
        assert_eq!(djb2_hash(cstr.to_bytes()), 0x46ceb3b4);

        cstr = CStr::from_bytes_with_nul(b"OpenProcess\0").unwrap();
        assert_eq!(djb2_hash(cstr.to_bytes()), 0x7136fdd6);

        cstr = CStr::from_bytes_with_nul(b"CreateToolhelp32Snapshot\0").unwrap();
        assert_eq!(djb2_hash(cstr.to_bytes()), 0x66851295);

        cstr = CStr::from_bytes_with_nul(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum\0").unwrap();
        assert_eq!(djb2_hash(cstr.to_bytes()), 0x8a9e3adf);
    }

    #[test]
    fn test_djb2_hash_str() {
        assert_eq!(djb2_hash("RegCreateKeyExW".as_bytes()), 0x46ceb3b4);
        assert_eq!(djb2_hash("OpenProcess".as_bytes()), 0x7136fdd6);
        assert_eq!(djb2_hash("CreateToolhelp32Snapshot".as_bytes()), 0x66851295);
        assert_eq!(djb2_hash("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum".as_bytes()), 0x8a9e3adf);
    }
}
