#![feature(link_llvm_intrinsics)]

// References:
//      https://samrambles.com/guides/window-hacking-with-rust/creating-a-dll-with-rust/index.html
//      https://github.com/stephenfewer/ReflectiveDLLInjection
//      https://github.com/memN0ps/venom-rs/blob/main/reflective_loader/src/lib.rs
use windows::{
    Win32::Foundation::{HINSTANCE, HWND},
    Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH},
    Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK},
    core::PCWSTR,
};
use hash_resolver::*;
use djb2macro::djb2;

let mut HINSTANCE h_app_instance = HINSTANCE(0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

// https://stackoverflow.com/questions/54999851/how-do-i-get-the-return-address-of-a-function
extern {
    #[link_name = "llvm.returnaddress"]
    #[no_inline]
    #[link_section = ".text"]
    fn return_address(a: i32) -> *const u8;
}

// Export for reflective injection
// Reference: https://github.com/stephenfewer/ReflectiveDLLInjection
#[no_mangle]
#[allow(non_snake_case, unused_variables)]
#[link_section = ".text"]
pub unsafe extern "system" fn RefLoader(lp_parameter: *mut ()) -> *const u8 {
    let ui_library_addr: *mut u8 = unsafe {return_address(0)};
}

// https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain
#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(h_inst_dll: HINSTANCE, dw_reason: u32, lp_reserved: *mut ()) -> bool {
    match dw_reason {
        DLL_QUERY_HMODULE => {

        },
        DLL_PROCESS_ATTACH => spawn_message(),
        _ => (),
    }

    true
}

fn spawn_message() {
    let message_str_w = to_wstring("Injected msg");
    let title_str_w = to_wstring("Injected DLL");

    unsafe {
        MessageBoxW(
            HWND(0),
            PCWSTR::from_raw(message_str_w.as_ptr()),
            PCWSTR::from_raw(title_str_w.as_ptr()),
            MB_OK,
        );
    }
}

pub fn to_wstring(value: &str) -> Vec<u16> {
    return value.encode_utf16().chain([0u16]).collect::<Vec<u16>>();
}
