#[cfg(target_os = "windows")]

mod resolve;
mod util;

use std::ffi::c_void;
use djb2macro::djb2;
use crate::util::to_wstring;

// Macro to convert address to function pointer.
// Reference: https://stackoverflow.com/a/46134764, https://doc.rust-lang.org/stable/std/mem/fn.transmute.html
macro_rules! addr_to_func_ptr {
    ($addr:expr, $t:ty) => {
        unsafe { ::std::mem::transmute::<*const (), $t>($addr as *const ()) }
    };
}

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
    let ret: i32 = message_box_w_ptr(0 as *mut c_void, to_wstring("Test msg").as_ptr(), to_wstring("Test title").as_ptr(), MB_OK);
    println!("Return value: {}", ret);
}
