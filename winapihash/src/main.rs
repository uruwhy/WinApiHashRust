#[cfg(target_os = "windows")]

use std::error::Error;
use {
    windows::core::PCWSTR,
    windows::Win32::Foundation::{
        HMODULE,
        FreeLibrary,
    },
    windows::Win32::System::{
        LibraryLoader::LoadLibraryW,
        SystemServices::{
            IMAGE_DOS_HEADER,
            IMAGE_DOS_SIGNATURE,
        },
    },
};


// Define return type for GetProcAddress
// Ref: https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Foundation/type.FARPROC.html
pub type FARPROC = unsafe extern "system" fn() -> isize;

// Convert rust string to wide Windows string
// Reference: https://github.com/microsoft/windows-rs/issues/973
fn to_wstring(value: &str) -> PCWSTR {
    let mut encoded = value.encode_utf16().collect::<Vec<_>>();
    encoded.push(0);
    PCWSTR::from_raw(encoded.as_ptr())
}

fn release_hmodule(h_module: HMODULE) {
    match unsafe { FreeLibrary(h_module) } {
        Ok(_) => (),
        Err(e) => {
            println!("FreeLibrary failed: {}", e);
        }
    }
}

// Helper function to iterate through DLL EAT
// Reference: https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
// Reference: https://github.com/LloydLabs/Windows-API-Hashing/blob/master/resolve.c
fn process_module_eat(module_name: &str) -> Result<(), Box<dyn Error>> {
    println!("Processing module: {}", module_name);

    // Get module handle
    let module_name_w = to_wstring(module_name);
    let h_module: HMODULE = unsafe { LoadLibraryW(module_name_w)? };
    if h_module.is_invalid() {
        Err("LoadLibraryW returned invalid HMODULE.")?
    }

    // Save pointer to library base (HMODULE is DLL base address)
    let library_base_ptr: *const u8 = h_module.0 as *const u8;

    // Read in DOS header
    let dos_header_ptr: *const IMAGE_DOS_HEADER = library_base_ptr as *const IMAGE_DOS_HEADER;

    // Debugging - display fields
    #[cfg(debug_assertions)]
    unsafe {
        println!("e_magic:    {:#06x}", (*dos_header_ptr).e_magic);
        println!("e_cblp:     {:#06x}", (*dos_header_ptr).e_cblp);
        println!("e_cp:       {:#06x}", (*dos_header_ptr).e_cp);
        println!("e_crlc:     {:#06x}", (*dos_header_ptr).e_crlc);
        println!("e_cparhdr:  {:#06x}", (*dos_header_ptr).e_cparhdr);
        println!("e_minalloc: {:#06x}", (*dos_header_ptr).e_minalloc);
        println!("e_maxalloc: {:#06x}", (*dos_header_ptr).e_maxalloc);
        println!("e_ss:       {:#06x}", (*dos_header_ptr).e_ss);
        println!("e_sp:       {:#06x}", (*dos_header_ptr).e_sp);
        println!("e_csum:     {:#06x}", (*dos_header_ptr).e_csum);
        println!("e_ip:       {:#06x}", (*dos_header_ptr).e_ip);
        println!("e_cs:       {:#06x}", (*dos_header_ptr).e_cs);
        println!("e_lfarlc:   {:#06x}", (*dos_header_ptr).e_lfarlc);
        println!("e_ovno:     {:#06x}", (*dos_header_ptr).e_ovno);
        println!("e_oemid:    {:#06x}", (*dos_header_ptr).e_oemid);
        println!("e_oeminfo:  {:#06x}", (*dos_header_ptr).e_oeminfo);

        // Bypass error for unaligned reference to packed field
        let lfanew: i32 = (*dos_header_ptr).e_lfanew;
        println!("e_lfanew:   {:#010x}", lfanew);
    }

    // Verify DOS header
    if unsafe { (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE } {
        release_hmodule(h_module);
        Err("Invalid DOS header - magic number mismatch.")?
    }

    Ok(())
}


fn main() {
    process_module_eat("kernel32.dll").unwrap();
}
