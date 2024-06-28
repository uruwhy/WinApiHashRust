use windows::core::PCWSTR;

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
pub fn to_wstring(value: &str) -> PCWSTR {
    let mut encoded = value.encode_utf16().collect::<Vec<_>>();
    encoded.push(0);
    PCWSTR::from_raw(encoded.as_ptr())
}


