#[cfg(target_os = "windows")]

mod resolve;
mod util;

use std::ffi::c_void;
use windows::core::PCWSTR;
use djb2macro::djb2;
use crate::util::*;

// HWND -> HANDLE -> void *
// LPCWSTR -> *const u16
// UINT -> u32
type FnMessageBoxW = fn(*mut c_void, *const u16, *const u16, u32) -> i32;

const MB_OK: u32 = 0x00000000;

fn main() {
    #[cfg(debug_assertions)] {
        println!("Printing target hashes:");
        resolve::print_target_hashes();
    }

    // Proof of concept. Get function pointer for MessageBoxW
    let message_box_w_ptr: FnMessageBoxW = addr_to_func_ptr!(resolve::resolve_api(djb2!("MessageBoxW"), "User32.dll").unwrap(), FnMessageBoxW);

    // Call MessageBoxW
    let message_str_w = to_wstring("Test msg");
    let title_str_w = to_wstring("Test title");
    let ret: i32 = message_box_w_ptr(0 as *mut c_void, message_str_w.as_ptr(), title_str_w.as_ptr(), MB_OK);
    println!("Return value: {}", ret);

    println!("The current directory is {}", std::env::current_dir().unwrap().display());
    let path_w = to_wstring("C:\\Users\\User\\Documents\\WinApiHashRust\\winapihash\\dll_to_inject\\target\\release\\toinject.dll");
    unsafe {
        let ret = windows::Win32::System::LibraryLoader::LoadLibraryW(PCWSTR::from_raw(path_w.as_ptr())).unwrap();
    };
}
