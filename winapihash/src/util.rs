use windows::core::PCWSTR;

// Convert rust string to wide Windows string
// Reference: https://github.com/microsoft/windows-rs/issues/973
pub fn to_wstring(value: &str) -> PCWSTR {
    let mut encoded = value.encode_utf16().collect::<Vec<_>>();
    encoded.push(0);
    PCWSTR::from_raw(encoded.as_ptr())
}
