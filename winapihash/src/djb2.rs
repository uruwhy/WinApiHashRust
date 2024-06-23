// Calculates DJB2 hash for given input bytes
// Reference: http://www.cse.yorku.ca/~oz/hash.html
pub fn djb2_hash(input: &[u8]) -> u32 {
	let mut hash: u32 = 5381;
	for c in input.iter() {
		hash = ((hash << 5) + hash) + (*c as u32); 
	}

	hash
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::ffi::CStr;

	#[test]
    fn test_djb2_hash() {
    	let mut cstr = CStr::from_bytes_with_nul(b"RegCreateKeyExW\0").unwrap();
    	let mut result = djb2_hash(cstr.to_bytes());
    	assert_eq!(result, 0x46ceb3b4);

    	cstr = CStr::from_bytes_with_nul(b"OpenProcess\0").unwrap();
    	result = djb2_hash(cstr.to_bytes());
    	assert_eq!(result, 0x7136fdd6);
    }
}