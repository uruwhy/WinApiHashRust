#[cfg(target_os = "windows")]

mod inject;
mod util;

cfg_if::cfg_if! {
    if #[cfg(debug_assertions)] {
        use std::ffi::c_void;
        use djb2macro::djb2;
        use hash_resolver::*;
        use crate::util::*;
    }
}

// HWND -> HANDLE -> void *
// LPCWSTR -> *const u16
// UINT -> u32
#[cfg(debug_assertions)]
type FnMessageBoxW = fn(*mut c_void, *const u16, *const u16, u32) -> i32;

#[cfg(debug_assertions)]
const MB_OK: u32 = 0x00000000;

fn main() {
    #[cfg(debug_assertions)] {
        println!("Printing target hashes:");
        print_target_hashes();

        // Proof of concept. Get function pointer for MessageBoxW
        let message_box_w_ptr: FnMessageBoxW = addr_to_func_ptr!(resolve_api(djb2!("MessageBoxW"), "User32.dll").unwrap(), FnMessageBoxW);

        // Call MessageBoxW
        let message_str_w = to_wstring("Test msg");
        let title_str_w = to_wstring("Test title");
        let ret: i32 = message_box_w_ptr(0 as *mut c_void, message_str_w.as_ptr(), title_str_w.as_ptr(), MB_OK);
        println!("MessageBoxW return value: {}", ret);
    }

    println!("The current directory is {}", std::env::current_dir().unwrap().display());
    /*let path_w = to_wstring("C:\\Users\\User\\Documents\\WinApiHashRust\\winapihash\\dll_to_inject\\target\\release\\toinject.dll");
    unsafe {
        windows::Win32::System::LibraryLoader::LoadLibraryW(PCWSTR::from_raw(path_w.as_ptr())).unwrap();
    };*/
}
