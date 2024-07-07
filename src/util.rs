// Convert rust string to wide Windows string
// Reference: https://github.com/microsoft/windows-rs/issues/973
pub fn to_wstring(value: &str) -> Vec<u16> {
    return value.encode_utf16().chain([0u16]).collect::<Vec<u16>>();
}
