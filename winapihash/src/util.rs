// Macro to convert address to function pointer.
// Reference: https://stackoverflow.com/a/46134764, https://doc.rust-lang.org/stable/std/mem/fn.transmute.html
#[macro_export]
macro_rules! addr_to_func_ptr {
    ($addr:expr, $t:ty) => {
        unsafe { ::std::mem::transmute::<*const (), $t>($addr as *const ()) }
    };
}

// Convert rust string to wide Windows string
// Reference: https://github.com/microsoft/windows-rs/issues/973
pub fn to_wstring(value: &str) -> Vec<u16> {
    return value.encode_utf16().chain([0u16]).collect::<Vec<u16>>();
}
